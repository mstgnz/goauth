package goauth

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// gitlabProvider allows authentication via gitlabProvider OAuth2.
type gitlabProvider struct {
	*goauth.OAuth2Config
}

// newGitlabProvider creates new gitlabProvider provider instance with some defaults.
func newGitlabProvider() goauth.Provider {
	return &gitlabProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "GitLab",
		AuthUrl:     "https://gitlab.com/oauth/authorize",
		TokenUrl:    "https://gitlab.com/oauth/token",
		UserApiUrl:  "https://gitlab.com/api/v4/user",
		Scopes:      []string{"read_user"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based the gitlabProvider user api.
// API reference: https://docs.gitlab.com/ee/api/users.html#for-admin
func (g *gitlabProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := g.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id        int    `json:"id"`
		Name      string `json:"name"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		AvatarUrl string `json:"avatar_url"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           strconv.Itoa(extracted.Id),
		Name:         extracted.Name,
		Username:     extracted.Username,
		Email:        extracted.Email,
		AvatarUrl:    extracted.AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
