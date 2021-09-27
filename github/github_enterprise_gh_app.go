// Package github wraps GitHub APIs that show up to be useful in the Headless
// codebase, aiming to make them easier to use in the project.
package github

import (
	"context"
	"net/http"
	"net/url"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/v32/github"
	"github.com/pkg/errors"
)

func (c *AppClient) CheckRepoPermissionsEnterprise(ctx context.Context, enterpriseUrl, repo string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	_, err = c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
	return err
}

func (c *AppClient) CreatePushHookEnterprise(ctx context.Context, enterpriseUrl, repo, hookURL, hookSecret string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
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

func (c *AppClient) GetZipballLinkEnterprise(ctx context.Context, enterpriseUrl, repo, ref string) (*url.URL, error) {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	api, err := c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
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

func (c *AppClient) GetBranchLastCommitShaEnterprise(ctx context.Context, enterpriseUrl, repo, branchName string) (string, error) {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return "", err
	}
	api, err := c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
	if err != nil {
		return "", err
	}

	branch, _, err := api.Repositories.GetBranch(ctx, owner, repo, branchName)
	if err != nil {
		return "", errors.Wrapf(err, "get commit sha for '%s/%s' failed", owner, repo)
	}

	return *branch.Commit.SHA, nil
}

func (c *AppClient) GetBranchesLastCommitShaEnterprise(ctx context.Context, enterpriseUrl, repo string, branches []string) (map[string]string, error) {
	branchesCommitSHA := make(map[string]string)
	for _, branch := range branches {
		if _, ok := branchesCommitSHA[branch]; !ok {
			lastCommitSHA, err := c.GetBranchLastCommitShaEnterprise(ctx, enterpriseUrl, repo, branch)
			if err != nil {
				return nil, err
			}
			branchesCommitSHA[branch] = lastCommitSHA
		}
	}
	return branchesCommitSHA, nil
}

func (c *AppClient) SetCommitStatusEnterprise(ctx context.Context, enterpriseUrl, repo, sha string, state CommitState, envUniqueName, description, url string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
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

func (c *AppClient) AddCommitCommentEnterprise(ctx context.Context, enterpriseUrl, repo, sha, content string) error {
	owner, repo, err := splitRepo(repo)
	if err != nil {
		return err
	}
	api, err := c.installationClientEnterprise(ctx, enterpriseUrl, owner, repo)
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

func (c *AppClient) installationClientEnterprise(ctx context.Context, enterpriseUrl, owner, repo string) (*github.Client, error) {
	tr := ghinstallation.NewAppsTransportFromPrivateKey(http.DefaultTransport, c.appID, c.privateKey)
	tr.BaseURL = enterpriseUrl
	api, err := github.NewEnterpriseClient(enterpriseUrl, enterpriseUrl, &http.Client{Transport: tr})
	if err != nil {
		return nil, err
	}

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

	return github.NewEnterpriseClient(enterpriseUrl, enterpriseUrl, &http.Client{
		Transport: ghinstallation.NewFromAppsTransport(tr, *inst.ID),
	})
}
