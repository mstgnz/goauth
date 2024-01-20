package goauth

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// giteaProvider allows authentication via giteaProvider OAuth2.
type giteaProvider struct {
	*goauth.OAuth2Config
}

// newGiteaProvider creates new giteaProvider provider instance with some defaults.
func newGiteaProvider() goauth.Provider {
	return &giteaProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "giteaProvider",
		AuthUrl:     "https://gitea.com/login/oauth/authorize",
		TokenUrl:    "https://gitea.com/login/oauth/access_token",
		UserApiUrl:  "https://gitea.com/api/v1/user",
		Scopes:      []string{"read:user", "user:email"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on giteaProvider's user api
// reference: https://try.gitea.io/api/swagger#/user/userGetCurrent
func (g *giteaProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
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
		Name      string `json:"full_name"`
		Username  string `json:"login"`
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
