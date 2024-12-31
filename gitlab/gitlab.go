package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/mstgnz/goauth"
	"github.com/mstgnz/goauth/config"

	"golang.org/x/oauth2"
)

// gitlabProvider allows authentication via gitlabProvider OAuth2.
type gitlabProvider struct {
	*config.OAuth2Config
	goauth.BaseProvider
}

// NewGitlabProvider creates new gitlabProvider provider instance with some defaults.
func NewGitlabProvider() goauth.Provider {
	return &gitlabProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "GitLab",
			AuthUrl:     "https://gitlab.com/oauth/authorize",
			TokenUrl:    "https://gitlab.com/oauth/token",
			UserApiUrl:  "https://gitlab.com/api/v4/user",
			Scopes:      []string{"read_user"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *gitlabProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *gitlabProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

// FetchUser returns a Credential instance based the gitlabProvider user api.
// API reference: https://docs.gitlab.com/ee/api/users.html#for-admin
func (p *gitlabProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
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
