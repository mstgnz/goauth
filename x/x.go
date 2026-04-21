package x

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type xProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewXProvider() goauth.Provider {
	return &xProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "X (Twitter)",
			AuthUrl:     "https://x.com/i/oauth2/authorize",
			TokenUrl:    "https://api.x.com/2/oauth2/token",
			UserApiUrl:  "https://api.x.com/2/users/me",
			Scopes:      []string{"users.read", "tweet.read"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *xProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Data struct {
			Id       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Data.Id,
		Name:         extracted.Data.Name,
		Username:     extracted.Data.Username,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *xProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *xProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL:  p.GetTokenUrl(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	newToken, err := config.TokenSource(p.GetContext(), token).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}
