package google

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// googleProvider allows authentication via googleProvider OAuth2.
type googleProvider struct {
	*goauth.OAuth2Config
}

// NewGoogleProvider creates new googleProvider provider instance with some defaults.
func NewGoogleProvider() goauth.Provider {
	return &googleProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "googleProvider",
		AuthUrl:     "https://accounts.google.com/o/oauth2/auth",
		TokenUrl:    "https://accounts.google.com/o/oauth2/token",
		UserApiUrl:  "https://www.googleapis.com/oauth2/v1/userinfo",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based the googleProvider's user api.
func (p *googleProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		AvatarUrl:    extracted.Picture,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.VerifiedEmail {
		user.Email = extracted.Email
	}

	return user, nil
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *googleProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint:     google.Endpoint,
	}

	return config.TokenSource(p.GetContext(), token).Token()
}

// ValidateConfig validates the provider configuration.
func (p *googleProvider) ValidateConfig() error {
	if p.GetClientId() == "" {
		return errors.New("client ID is required")
	}
	if p.GetClientSecret() == "" {
		return errors.New("client secret is required")
	}
	if p.GetRedirectUrl() == "" {
		return errors.New("redirect URL is required")
	}
	return nil
}
