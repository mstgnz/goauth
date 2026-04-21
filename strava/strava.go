package strava

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type stravaProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewStravaProvider() goauth.Provider {
	return &stravaProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Strava",
			AuthUrl:     "https://www.strava.com/oauth/authorize",
			TokenUrl:    "https://www.strava.com/oauth/token",
			UserApiUrl:  "https://www.strava.com/api/v3/athlete",
			Scopes:      []string{"read", "profile:read_all"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *stravaProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id        int    `json:"id"`
		FirstName string `json:"firstname"`
		LastName  string `json:"lastname"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		Profile   string `json:"profile"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           strconv.Itoa(extracted.Id),
		Name:         extracted.FirstName + " " + extracted.LastName,
		Username:     extracted.Username,
		Email:        extracted.Email,
		AvatarUrl:    extracted.Profile,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *stravaProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *stravaProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
