package github

import (
	"fmt"

	"github.com/google/go-github/v32/github"
)

// InstallationNotFoundError describes a situation when the Headless GitHub App
// is not installed on a GitHub repo.
type InstallationNotFoundError struct {
	Repo  string
	Cause *github.ErrorResponse
}

func (e *InstallationNotFoundError) Error() string {
	return fmt.Sprintf("installation ID search failed for %q", e.Repo)
}

// BadRepoFormatError describes a repo name that could not be properly parsed.
type BadRepoFormatError struct {
	Repo string
}

func (e *BadRepoFormatError) Error() string {
	return fmt.Sprintf("bad app repo format: %q", e.Repo)
}

type RepoNotFoundError struct {
	Repo string
}

func (e *RepoNotFoundError) Error() string {
	return fmt.Sprintf("repo %q not found", e.Repo)
}

type WrongGitHubCodeError struct {
}

func (e *WrongGitHubCodeError) Error() string {
	return "Invalid GitHub authorize code"
}
