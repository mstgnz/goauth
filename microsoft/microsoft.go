package microsoft

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
)

// microsoftProvider allows authentication via Microsoft OAuth2.
type microsoftProvider struct {
	*config.OAuth2Config
	provider.BaseProvider
}

// NewMicrosoftProvider creates new Microsoft provider instance with some defaults.
func NewMicrosoftProvider() provider.Provider {
	return &microsoftProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Microsoft",
			AuthUrl:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenUrl:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserApiUrl:  "https://graph.microsoft.com/v1.0/me",
			Scopes:      []string{"User.Read"},
			Pkce:        true,
		},
		BaseProvider: provider.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *microsoftProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *microsoftProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

// FetchUser returns a Credential instance based on the microsoftProvider's user api.
// API reference:  https://learn.microsoft.com/en-us/azure/active-directory/develop/userinfo
// Graph explorer: https://developer.microsoft.com/en-us/graph/graph-explorer
func (p *microsoftProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id    string `json:"id"`
		Name  string `json:"displayName"`
		Email string `json:"mail"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
