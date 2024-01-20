package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// oidcProvider allows authentication via OpenID Connect (oidcProvider) OAuth2 provider.
type oidcProvider struct {
	*goauth.OAuth2Config
}

// newOidcProvider creates new OpenID Connect (oidcProvider) provider instance with some defaults.
func newOidcProvider() goauth.Provider {
	return &oidcProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "oidcProvider",
		Scopes: []string{
			"openid", // minimal requirement to return the id
			"email",
			"profile",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based the provider's user api.
// API reference: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
func (p *oidcProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"sub"`
		Name          string `json:"name"`
		Username      string `json:"preferred_username"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Username:     extracted.Username,
		AvatarUrl:    extracted.Picture,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.EmailVerified {
		user.Email = extracted.Email
	}

	return user, nil
}
