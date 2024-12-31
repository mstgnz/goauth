package facebook

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// facebookProvider allows authentication via Facebook OAuth2.
type facebookProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

// NewFacebookProvider creates new Facebook provider instance with some defaults.
func NewFacebookProvider() goauth.Provider {
	return &facebookProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Facebook",
			AuthUrl:     facebook.Endpoint.AuthURL,
			TokenUrl:    facebook.Endpoint.TokenURL,
			UserApiUrl:  "https://graph.facebook.com/v18.0/me",
			Scopes:      []string{"email", "public_profile"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

// FetchUser returns a Credential instance based on the facebookProvider's user api.
// API reference: https://developers.facebook.com/docs/graph-api/reference/user/
func (p *facebookProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id      string
		Name    string
		Email   string
		Picture struct {
			Data struct{ Url string }
		}
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		AvatarUrl:    extracted.Picture.Data.Url,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}

// ValidateConfig validates the provider configuration.
func (p *facebookProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *facebookProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	return p.BaseProvider.RefreshTokenNotSupported()
}
