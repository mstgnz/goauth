package twitch

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

// twitchProvider allows authentication via Twitch OAuth2.
type twitchProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

// NewTwitchProvider creates new Twitch provider instance with some defaults.
func NewTwitchProvider() goauth.Provider {
	return &twitchProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Twitch",
			AuthUrl:     "https://id.twitch.tv/oauth2/authorize",
			TokenUrl:    "https://id.twitch.tv/oauth2/token",
			UserApiUrl:  "https://api.twitch.tv/helix/users",
			Scopes:      []string{"user:read:email"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *twitchProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *twitchProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

// FetchUser returns a Credential instance based the twitchProvider's user api.
// API reference: https://dev.twitch.tv/docs/api/reference#get-users
func (p *twitchProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Data []struct {
			Id              string `json:"id"`
			Login           string `json:"login"`
			DisplayName     string `json:"display_name"`
			Email           string `json:"email"`
			ProfileImageUrl string `json:"profile_image_url"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	if len(extracted.Data) == 0 {
		return nil, errors.New("failed to fetch Credential data")
	}

	user := &goauth.Credential{
		Id:           extracted.Data[0].Id,
		Name:         extracted.Data[0].DisplayName,
		Username:     extracted.Data[0].Login,
		Email:        extracted.Data[0].Email,
		AvatarUrl:    extracted.Data[0].ProfileImageUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}

// FetchRawData implements goauth.FetchRawData interface.
// This differs from oAuth2Provider because twitchProvider requires the `Client-Id` header.
func (p *twitchProvider) FetchRawData(token *oauth2.Token) ([]byte, error) {
	req, err := http.NewRequest("GET", p.GetUserApiUrl(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Client-Id", p.GetClientId())

	return p.SendRawUserDataRequest(req, token)
}
