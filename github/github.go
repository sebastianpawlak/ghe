// Package github wraps GitHub APIs that show up to be useful in the Headless
// codebase, aiming to make them easier to use in the project.
package github

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/golang-jwt/jwt"
	"github.com/google/go-github/v32/github"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

type CommitState string

// Commit states are defined by github API
// https://docs.github.com/en/rest/reference/repos#create-a-commit-status--parameters
var (
	CommitStateFailure CommitState = "failure"
	CommitStateSuccess CommitState = "success"
	CommitStateError   CommitState = "error"
	CommitStatePending CommitState = "pending"
)

// temporary solution to make testing easier, please refactor.
//go:generate mockgen -source=$GOFILE -destination=$PWD/internal/lib/github/mocks/${GOFILE} -package=mocks
type RepoAppClient interface {
	CheckRepoPermissions(ctx context.Context, repo string) error
	CreatePushHook(ctx context.Context, repo, hookURL, hookSecret string) error
	GetZipballLink(ctx context.Context, repo, ref string) (*url.URL, error)
	GetBranchLastCommitSha(ctx context.Context, repo, branchName string) (string, error)
	GetBranchesLastCommitSha(ctx context.Context, repo string, branches []string) (map[string]string, error)
	SetCommitStatus(ctx context.Context, repo, sha string, state CommitState, envUniqueName, description, url string) error
	AddCommitComment(ctx context.Context, repo, sha, content string) error
}

type WebhookURL string // FIXME(akavel): config

//go:generate mockgen -source=$GOFILE -destination=$PWD/internal/lib/github/mocks/${GOFILE} -package=mocks
type RepoOAuthClient interface {
	AcquireToken(ctx context.Context, oauthCode string) (*oauth2.Token, error)
	CheckRepoPermissions(ctx context.Context, repo string, cred Cred) error
	ListUserReposForApp(ctx context.Context, cred Cred) ([]*github.Repository, error)
	ListUserBranchesForRepo(ctx context.Context, cred Cred, owner, repo string) ([]*github.Branch, error)
}

// Cred represents some GitHub credential(s) allowing for authorization into
// its API. It should be enough to set just one of this struct's fields. The
// fields are expected to be tried in order in which they're defined in this
// struct.
type Cred struct {
	// PersonalAccessToken is a per-user broad-permissions GitHub API token, as
	// is commonly used for SSH login to GitHub.
	//
	// Deprecated: This is still used in our e2e tests, but is too powerful vs.
	// OAuthToken (making e2e tests not representative), so we should delete
	// this and migrate to OAuthToken in e2e tests.
	PersonalAccessToken string
	// OAuthCode is a one-time OAuth2 Code, which can get translated to
	// OAuthToken through our GitHub app secret.
	//
	// Deprecated: OAuthToken should be used instead
	OAuthCode string
	// OAuthToken is an OAuth2 Token generated from a one-time OAuth2 Code +
	// our GitHub app secret.
	OAuthToken *oauth2.Token
}

// AppClient manages communication with the GitHub API on behalf of the Headless project.
//
// IMPORTANT NOTE: we can't store *ghinstallation.AppsTransport due to a data
// race (through a breach of an interface contract) there, see:
// https://github.com/bradleyfalzon/ghinstallation/issues/20
// TODO: review the ghinstallation library, fix any bugs spotted (incl. a data leak mentioned in above link) and upstream the fixes.
type AppClient struct {
	appID      int64
	privateKey *rsa.PrivateKey
}

type AppOptions struct {
	ID         int64
	PrivateKey []byte
}

func NewAppClient2(opt *AppOptions) (*AppClient, error) {
	return NewAppClient(opt.ID, opt.PrivateKey)
}

// NewAppClient creates a AppClient based on App ID assigned by GitHub to Headless, and the corresponding private key (in PEM format).
func NewAppClient(appID int64, privateKey []byte) (*AppClient, error) {
	// TODO: Context, timeouts, GH rate limiting (https://github.com/google/go-github#rate-limiting)

	// For now, assuming RSA, same as in ghinstallation.NewAppsTransport
	k, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "cannot initialize GitHub client: could not parse private key")
	}
	return &AppClient{
		appID:      appID,
		privateKey: k,
	}, nil
}

// CheckRepoPermissions checks if the Headless GitHub App has necessary
// permissions in the specified GitHub repo.
//
// TODO: Currently, the function only checks if the App is installed in the
// specified repo. In future, we could verify specific permissions on a more
// fine-grained level.
func (c *AppClient) CheckRepoPermissions(ctx context.Context, repo string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	_, err = c.installationClient(ctx, owner, repo)
	return err
}

// CreatePushHook asks the GitHub API to add a "push" webhook to the specified
// repo (must have `$OWNER/$NAME` format), on behalf of the Headless GitHub
// App. The hookSecret will be passed as part of the payload to hookURL.
func (c *AppClient) CreatePushHook(ctx context.Context, repo, hookURL, hookSecret string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return err
	}

	_, _, err = api.Repositories.CreateHook(ctx, owner, repo, &github.Hook{
		Config: map[string]interface{}{
			"content_type": "json",
			"url":          hookURL,
			"secret":       hookSecret,
		},
		Events: []string{"push"},
	})
	if err != nil {
		return errors.Wrapf(err, "creating github webhook for '%s/%s' failed", owner, repo)
	}

	return nil
}

// UpdatePushHook asks the GitHub API to update a "push" webhook to the specified
// repo (must have `$OWNER/$NAME` format), on behalf of the Headless GitHub
// App. The hookSecret will be passed as part of the payload to hookURL.
func (c *AppClient) UpdatePushHook(ctx context.Context, repo, hookURL, hookSecret string) error {
	// TODO this is just for batch tool usage if you want to use this inside the production code, please handle errors properly.
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return err
	}

	hooks, _, err := api.Repositories.ListHooks(ctx, owner, repo, &github.ListOptions{})
	if err != nil {
		return errors.Wrapf(err, "listing github webhooks for '%s/%s' failed", owner, repo)
	}
	for _, hook := range hooks {
		// we are comparing just the prefix to remove also an old version of the webhooks
		if strings.HasPrefix(hook.Config["url"].(string), hookURL) {
			_, err = api.Repositories.DeleteHook(ctx, owner, repo, *hook.ID)
			if err != nil {
				log.WithError(err).Errorf("hook delete for '%s/%s' failed", owner, repo)
				return err
			}
			log.Infof("%s webhook deleted for '%s/%s'", hookURL, owner, repo)
		}
	}
	err = c.CreatePushHook(
		ctx,
		fmt.Sprintf("%s/%s", owner, repo),
		hookURL,
		hookSecret)

	if err != nil {
		log.WithError(err).Errorf("creating github webhook for '%s/%s' failed", owner, repo)
		return err
	}
	log.Infof("%s webhook created", hookURL)

	return nil
}

// Get a link for downloading a zip archive of a repo (specified in
// `$OWNER/$NAME` format). Per GitHub API docs, the link is expected to be
// valid for 5 minutes (see: https://docs.github.com/en/rest/reference/repos#download-a-repository-archive-zip)
func (c *AppClient) GetZipballLink(ctx context.Context, repo, ref string) (*url.URL, error) {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	link, _, err := api.Repositories.GetArchiveLink(ctx, owner, repo, github.Zipball, &github.RepositoryContentGetOptions{
		Ref: ref,
	}, true) // true for redirects seems sensible
	if err != nil {
		return nil, errors.Wrapf(err, "getting github zipball link for '%s/%s'", owner, repo)
	}
	return link, nil
}

func splitRepo(repo string) (string, string, error) {
	path := strings.SplitN(repo, "/", 2)
	if len(path) != 2 {
		return "", "", errors.WithStack(&BadRepoFormatError{repo})
	}
	return path[0], path[1], nil
}

func (c *AppClient) installationClient(ctx context.Context, owner, repo string) (*github.Client, error) {
	tr := ghinstallation.NewAppsTransportFromPrivateKey(http.DefaultTransport, c.appID, c.privateKey)
	api := github.NewClient(&http.Client{
		Transport: tr,
	})

	// NOTE: we don't close rs.Body, as it's already closed internally by the go-github package methods used in this func.
	inst, _, err := api.Apps.FindRepositoryInstallation(ctx, owner, repo)
	if err != nil {
		cause, _ := err.(*github.ErrorResponse)
		if cause != nil && cause.Response != nil && cause.Response.StatusCode == http.StatusNotFound {
			// TODO(akavel): don't know why, but errors.WithStack alone seems to not give stack :/
			return nil, errors.Wrapf(&InstallationNotFoundError{
				Repo:  owner + "/" + repo,
				Cause: cause,
			}, "installation not found")
		}
		return nil, errors.Wrapf(err, "installation ID search failed for '%s/%s'", owner, repo)
	}

	return github.NewClient(&http.Client{
		Transport: ghinstallation.NewFromAppsTransport(tr, *inst.ID),
	}), nil
}

func (c *AppClient) GetBranchLastCommitSha(ctx context.Context, repo, branchName string) (string, error) {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return "", err
	}

	branch, _, err := api.Repositories.GetBranch(ctx, owner, repo, branchName)
	if err != nil {
		return "", errors.Wrapf(err, "get commit sha for '%s/%s' failed", owner, repo)
	}

	return *branch.Commit.SHA, nil
}

func (c *AppClient) SetCommitStatus(ctx context.Context, repo, sha string, state CommitState, envUniqueName, description, url string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return err
	}
	stateStr := string(state)
	_, _, err = api.Repositories.CreateStatus(ctx, owner, repo, sha, &github.RepoStatus{
		State:       &stateStr,
		TargetURL:   &url,
		Description: &description,
		Context:     &envUniqueName,
	})
	if err != nil {
		return errors.Wrapf(err, "set status for '%s/%s/%s' failed", owner, repo, sha)
	}

	return nil
}

func (c *AppClient) AddCommitComment(ctx context.Context, repo, sha, content string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClient(ctx, owner, repo)
	if err != nil {
		return err
	}
	_, _, err = api.Repositories.CreateComment(ctx, owner, repo, sha, &github.RepositoryComment{
		Body: &content,
	})
	if err != nil {
		return errors.Wrapf(err, "set comment for '%s/%s/%s' failed", owner, repo, sha)
	}

	return nil
}

func (c *AppClient) GetBranchesLastCommitSha(ctx context.Context, repo string, branches []string) (map[string]string, error) {
	branchesCommitSHA := make(map[string]string)
	for _, branch := range branches {
		if _, ok := branchesCommitSHA[branch]; !ok {
			lastCommitSHA, err := c.GetBranchLastCommitSha(ctx, repo, branch)
			if err != nil {
				return nil, err
			}
			branchesCommitSHA[branch] = lastCommitSHA
		}
	}
	return branchesCommitSHA, nil
}

var _ RepoAppClient = (*AppClient)(nil)

type OAuthClient struct {
	clientID string
	secret   string
}

type OAuthOptions struct {
	ClientID string
	Secret   string
}

func NewOAuthClient2(opts *OAuthOptions) *OAuthClient {
	return NewOAuthClient(opts.ClientID, opts.Secret)
}

func NewOAuthClient(clientID, secret string) *OAuthClient {
	return &OAuthClient{
		clientID: clientID,
		secret:   secret,
	}
}

func (c *OAuthClient) AcquireToken(ctx context.Context, oauthCode string) (*oauth2.Token, error) {
	token, err := c.oauthConf().Exchange(ctx, oauthCode)
	if err != nil {
		return nil, &WrongGitHubCodeError{}
	}
	return token, nil
}

// TODO(asow) separate repo owner and repo name
func (c *OAuthClient) CheckRepoPermissions(ctx context.Context, repo string, cred Cred) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	client, err := c.client(ctx, cred)
	if err != nil {
		return err
	}
	_, res, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		if res != nil && res.StatusCode == http.StatusNotFound {
			return errors.Wrap(&RepoNotFoundError{repo}, "repo not found")
		}
		return errors.Wrapf(err, "repo %s/%s get error", owner, repo)
	}
	return nil
}

func (c *OAuthClient) ListUserReposForApp(ctx context.Context, cred Cred) ([]*github.Repository, error) {

	client, err := c.client(ctx, cred)
	if err != nil {
		return nil, err
	}

	var repos []*github.Repository

	// List github app installations accessible for authenticated user
	// https://docs.github.com/en/rest/reference/apps#list-app-installations-accessible-to-the-user-access-token
	// TODO(akavel): add support for github results pagination
	installs, _, err := client.Apps.ListUserInstallations(ctx, nil)
	if err != nil {
		if e, ok := err.(*github.ErrorResponse); ok &&
			e.Response != nil && e.Response.StatusCode == http.StatusUnauthorized {
			return nil, &WrongGitHubCodeError{}
		}
		return nil, errors.Wrap(err, "listing user installations")
	}
	for _, inst := range installs {
		pagination := &github.ListOptions{}
		for {
			// List repositories accessible to authenticated user for specific installation ID
			// https://docs.github.com/en/rest/reference/apps#list-repositories-accessible-to-the-user-access-token
			reposPage, resp, err := client.Apps.ListUserRepos(ctx, inst.GetID(), pagination)
			if err != nil {
				if e, ok := err.(*github.ErrorResponse); ok &&
					e.Response != nil && e.Response.StatusCode == http.StatusUnauthorized {
					return nil, &WrongGitHubCodeError{}
				}
				return nil, errors.Wrapf(err, "listing repos for inst %v for %v", inst.GetID(), inst.GetAccount().GetLogin())
			}
			repos = append(repos, reposPage...)
			if resp.NextPage == 0 {
				break
			}
			pagination.Page = resp.NextPage
		}
	}
	return repos, nil
}

func (c *OAuthClient) ListUserBranchesForRepo(ctx context.Context, cred Cred, owner, repo string) ([]*github.Branch, error) {
	client, err := c.client(ctx, cred)
	if err != nil {
		return nil, err
	}

	var branches []*github.Branch

	pagination := &github.BranchListOptions{}
	for {
		branchesPage, resp, err := client.Repositories.ListBranches(ctx, owner, repo, pagination)
		if err != nil {
			if e, ok := err.(*github.ErrorResponse); ok &&
				e.Response != nil && e.Response.StatusCode == http.StatusUnauthorized {
				return nil, &WrongGitHubCodeError{}
			}
			return nil, errors.Wrapf(err, "listing branches for GitHub account %v for repo: %v", owner, repo)
		}
		branches = append(branches, branchesPage...)
		if resp.NextPage == 0 {
			break
		}
		pagination.Page = resp.NextPage
	}
	return branches, nil
}

func (c *OAuthClient) oauthConf() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.secret,
		Endpoint:     githuboauth.Endpoint,
	}
}

func (c *OAuthClient) client(ctx context.Context, cred Cred) (*github.Client, error) {
	if cred.PersonalAccessToken != "" {
		client := oauth2.NewClient(ctx, &tokenSource{accessToken: cred.PersonalAccessToken})
		return github.NewClient(client), nil
	}
	token := cred.OAuthToken
	if cred.OAuthCode != "" {
		var err error
		token, err = c.AcquireToken(ctx, cred.OAuthCode)
		if err != nil {
			return nil, err
		}
	}
	return github.NewClient(c.oauthConf().Client(ctx, token)), nil
}

func (c *OAuthClient) GetAuthCodeURL(redirectURL, state string) string {
	oauthConf := &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.secret,
		RedirectURL:  redirectURL,
		Endpoint:     githuboauth.Endpoint,
	}
	return oauthConf.AuthCodeURL(state)
}

type tokenSource struct {
	accessToken string
}

func (t *tokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.accessToken,
	}
	return token, nil
}

var _ RepoOAuthClient = (*OAuthClient)(nil)
