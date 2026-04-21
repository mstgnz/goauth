package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type oidcProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewOidcProvider() goauth.Provider {
	return &oidcProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "OpenID Connect",
			Scopes:      []string{"openid", "profile", "email"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *oidcProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Sub      string `json:"sub"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Picture  string `json:"picture"`
		Username string `json:"preferred_username"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Sub,
		Name:         extracted.Name,
		Email:        extracted.Email,
		Username:     extracted.Username,
		AvatarUrl:    extracted.Picture,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *oidcProvider) ValidateConfig() error {
	if err := p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl()); err != nil {
		return err
	}
	if p.GetAuthUrl() == "" || p.GetTokenUrl() == "" || p.GetUserApiUrl() == "" {
		return errors.New("auth url, token url and user api url are required")
	}
	return nil
}

func (p *oidcProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

	newToken, err := config.TokenSource(p.GetContext(), token).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}
