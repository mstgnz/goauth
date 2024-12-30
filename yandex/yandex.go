package yandex

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

// yandexProvider allows authentication via yandexProvider OAuth2.
type yandexProvider struct {
	*config.OAuth2Config
}

// NewYandexProvider creates new yandexProvider provider instance with some defaults.
// Docs: https://yandex.ru/dev/id/doc/en/
func NewYandexProvider() provider.Provider {
	return &yandexProvider{&config.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "yandexProvider",
		AuthUrl:     yandex.Endpoint.AuthURL,
		TokenUrl:    yandex.Endpoint.TokenURL,
		UserApiUrl:  "https://login.yandex.ru/info",
		Scopes:      []string{"login:email", "login:avatar", "login:info"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on yandexProvider's user api.
// API reference: https://yandex.ru/dev/id/doc/en/user-information#response-format
func (p *yandexProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
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
		Name          string `json:"real_name"`
		Username      string `json:"login"`
		Email         string `json:"default_email"`
		IsAvatarEmpty bool   `json:"is_avatar_empty"`
		AvatarId      string `json:"default_avatar_id"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Username:     extracted.Username,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if !extracted.IsAvatarEmpty {
		user.AvatarUrl = "https://avatars.yandex.net/get-yapic/" + extracted.AvatarId + "/islands-200"
	}

	return user, nil
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *yandexProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

// ValidateConfig validates the provider configuration.
func (p *yandexProvider) ValidateConfig() error {
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
