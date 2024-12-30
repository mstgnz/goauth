package gitea

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"
	"golang.org/x/oauth2"
)

// giteaProvider allows authentication via Gitea OAuth2.
type giteaProvider struct {
	*config.OAuth2Config
	provider.BaseProvider
}

// NewGiteaProvider creates new Gitea provider instance with some defaults.
func NewGiteaProvider() provider.Provider {
	return &giteaProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Gitea",
			AuthUrl:     "https://gitea.com/login/oauth/authorize",
			TokenUrl:    "https://gitea.com/login/oauth/access_token",
			UserApiUrl:  "https://gitea.com/api/v1/user",
			Scopes:      []string{"read:user"},
			Pkce:        true,
		},
		BaseProvider: provider.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *giteaProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *giteaProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL: p.GetTokenUrl(),
		},
	}

	return config.TokenSource(p.GetContext(), token).Token()
}

// FetchUser returns a Credential instance based on giteaProvider's user api
// reference: https://try.gitea.io/api/swagger#/user/userGetCurrent
func (g *giteaProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
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

	user := &config.Credential{
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
