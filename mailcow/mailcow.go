package mailcow

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type mailcowProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewMailcowProvider() goauth.Provider {
	return &mailcowProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Mailcow",
			Scopes:      []string{"profile", "email"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *mailcowProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
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
		Name     string `json:"name"`
		Email    string `json:"email"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Username:     extracted.Username,
		Name:         extracted.Name,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *mailcowProvider) ValidateConfig() error {
	if err := p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl()); err != nil {
		return err
	}
	if p.GetAuthUrl() == "" || p.GetTokenUrl() == "" || p.GetUserApiUrl() == "" {
		return errors.New("auth url, token url and user api url are required")
	}
	return nil
}

func (p *mailcowProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
