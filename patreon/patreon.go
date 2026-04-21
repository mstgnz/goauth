package patreon

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type patreonProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewPatreonProvider() goauth.Provider {
	return &patreonProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Patreon",
			AuthUrl:     "https://www.patreon.com/oauth2/authorize",
			TokenUrl:    "https://www.patreon.com/api/oauth2/token",
			UserApiUrl:  "https://www.patreon.com/api/oauth2/v2/identity",
			Scopes:      []string{"identity"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *patreonProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
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
			Id         string `json:"id"`
			Attributes struct {
				FullName string `json:"full_name"`
				Email    string `json:"email"`
				ImageUrl string `json:"image_url"`
			} `json:"attributes"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Data.Id,
		Name:         extracted.Data.Attributes.FullName,
		Email:        extracted.Data.Attributes.Email,
		AvatarUrl:    extracted.Data.Attributes.ImageUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *patreonProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *patreonProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

	return config.TokenSource(p.GetContext(), token).Token()
}
