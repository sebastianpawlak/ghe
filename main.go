package main

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/sebastianpawlak/github/github"
	gh "github.com/sebastianpawlak/github/github"
)

func main() {
	//testGHAppWPESVC()
	testOauthAppWPESVC()
}

func testOauthAppWPESVC() {
	ctx := context.Background()
	clientID := "add real client id here"
	clientSecret := "add real client secret here"
	client := gh.NewOAuthClient(clientID, clientSecret)

	state := "test_state"
	authCodeUrl := client.GetAuthCodeURLEnterprise("http://localhost:34521/cli/auth/github/", state)
	log.Infof("Auth code URL: %s", authCodeUrl)
	// use url in browser to receive url after redirection with "code" param, which is authCode (used below)

	authCode := "add code from browser"
	token, err := client.AcquireTokenEnterprise(ctx, authCode)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("OAuth token: %s", token)

	cred := gh.Cred{
		//OAuthCode:  authCode,
		OAuthToken: token,
	}

	enterpriseUrl := github.GitHubEnterpriseServerUrl + "/api/v3"
	repoE := "thea/private-nodejs-app-1" // owner/repo
	//refE := "main"
	err = client.CheckRepoPermissionsEnterprise(ctx, enterpriseUrl, repoE, cred)
	if err != nil {
		log.Fatal(err.Error())
	}

	repos, err := client.ListUserReposForAppEnterprise(ctx, enterpriseUrl, cred)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("User repos: %v", repos)

	owner := "thea" // GH username
	repoWithoutOwner := "private-nodejs-app-1"
	branches, err := client.ListUserBranchesForRepoEnterprise(ctx, enterpriseUrl, cred, owner, repoWithoutOwner)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("Repo's branches: %s", *branches[0].Name)
}

func testGHAppWPESVC() {
	ctx := context.Background()

	client, err := gh.NewAppClient(1, []byte(`
-----BEGIN RSA PRIVATE KEY-----
... add real private key hehe
-----END RSA PRIVATE KEY-----`))

	if err != nil {
		log.Fatal(err.Error())
	}

	log.Info("GitHub Enterprise Server")

	repoE := "thea/private-nodejs-app-1"
	refE := "main"
	enterpriseUrl := "https://github.nodeengine.wpesvc.pl/api/v3"
	//hookUrl := "https://webhook.sieve.ovh"
	//hookSecret := "my_secret_for_hook"

	err = client.CheckRepoPermissionsEnterprise(ctx, enterpriseUrl, repoE)
	if err != nil {
		log.Fatal(err.Error())
	}

	// works
	/*
		err = client.CreatePushHookEnterprise(ctx, enterpriseUrl, repoE, hookUrl, hookSecret)
		if err != nil {
			log.Fatal(err.Error())
		}*/

	commitSha, err := client.GetBranchLastCommitShaEnterprise(ctx, enterpriseUrl, repoE, refE)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("Last commit sha: %s", commitSha)

	// works
	/*
		commitShas, err := client.GetBranchesLastCommitShaEnterprise(ctx, enterpriseUrl, repoE, []string{refE})
		if err != nil {
			log.Fatal(err.Error())
		}
		log.Infof("Last commit shas: %v", commitShas)*/
	/*
		err = client.SetCommitStatusEnterprise(ctx, enterpriseUrl, repoE, commitSha, gh.CommitStateSuccess, "my_env_unique_name", "my_desc", "https://status.sieve.ovh")
		if err != nil {
			log.Fatal(err.Error())
		}*/

	// works
	/*
		err = client.AddCommitCommentEnterprise(ctx, enterpriseUrl, repoE, commitSha, "my super comment")
		if err != nil {
			log.Fatal(err.Error())
		}*/

	urlE, err := client.GetZipballLinkEnterprise(ctx, enterpriseUrl, repoE, refE)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Info(urlE)
}
