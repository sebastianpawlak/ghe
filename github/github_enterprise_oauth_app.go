// Package github wraps GitHub APIs that show up to be useful in the Headless
// codebase, aiming to make them easier to use in the project.
package github

import (
	"context"
	"net/http"

	"github.com/google/go-github/v32/github"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const GitHubEnterpriseServerUrl = "add real url here"

var Endpoint = oauth2.Endpoint{
	AuthURL:  GitHubEnterpriseServerUrl + "/login/oauth/authorize",
	TokenURL: GitHubEnterpriseServerUrl + "/login/oauth/access_token",
}

func (c *OAuthClient) GetAuthCodeURLEnterprise(redirectURL, state string) string {
	oauthConf := &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.secret,
		RedirectURL:  redirectURL,
		Endpoint:     Endpoint,
	}
	return oauthConf.AuthCodeURL(state)
}

func (c *OAuthClient) oauthConfEnterprise() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.secret,
		Endpoint:     Endpoint,
	}
}

func (c *OAuthClient) AcquireTokenEnterprise(ctx context.Context, oauthCode string) (*oauth2.Token, error) {
	token, err := c.oauthConfEnterprise().Exchange(ctx, oauthCode)
	if err != nil {
		return nil, &WrongGitHubCodeError{}
	}
	return token, nil
}

func (c *OAuthClient) clientEnterprise(ctx context.Context, enterpriseUrl string, cred Cred) (*github.Client, error) {
	if cred.PersonalAccessToken != "" {
		client := oauth2.NewClient(ctx, &tokenSource{accessToken: cred.PersonalAccessToken})
		return github.NewClient(client), nil
	}
	token := cred.OAuthToken
	if cred.OAuthCode != "" {
		var err error
		token, err = c.AcquireTokenEnterprise(ctx, cred.OAuthCode)
		if err != nil {
			return nil, err
		}
	}
	return github.NewEnterpriseClient(enterpriseUrl, enterpriseUrl, c.oauthConfEnterprise().Client(ctx, token))
}

func (c *OAuthClient) CheckRepoPermissionsEnterprise(ctx context.Context, enterpriseUrl, repo string, cred Cred) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	client, err := c.clientEnterprise(ctx, enterpriseUrl, cred)
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

func (c *OAuthClient) ListUserReposForAppEnterprise(ctx context.Context, enterpriseUrl string, cred Cred) ([]*github.Repository, error) {

	client, err := c.clientEnterprise(ctx, enterpriseUrl, cred)
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

func (c *OAuthClient) ListUserBranchesForRepoEnterprise(ctx context.Context, enterpriseUrl string, cred Cred, owner, repo string) ([]*github.Branch, error) {
	client, err := c.clientEnterprise(ctx, enterpriseUrl, cred)
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
