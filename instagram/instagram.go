package instagram

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
)

// instagramProvider allows authentication via Instagram OAuth2.
type instagramProvider struct {
	*config.OAuth2Config
	provider.BaseProvider
}

// NewInstagramProvider creates new Instagram provider instance with some defaults.
func NewInstagramProvider() provider.Provider {
	return &instagramProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Instagram",
			AuthUrl:     "https://api.instagram.com/oauth/authorize",
			TokenUrl:    "https://api.instagram.com/oauth/access_token",
			UserApiUrl:  "https://graph.instagram.com/me",
			Scopes:      []string{"user_profile"},
			Pkce:        true,
		},
		BaseProvider: provider.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *instagramProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *instagramProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	return p.BaseProvider.RefreshTokenNotSupported()
}

// FetchUser returns a Credential instance based on the Instagram's user api.
// API reference: https://developers.facebook.com/docs/instagram-basic-display-api/reference/user#fields
func (p *instagramProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id       string `json:"id"`
		Username string `json:"username"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:           extracted.Id,
		Username:     extracted.Username,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}