package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/twitch"
)

// twitchProvider allows authentication via twitchProvider OAuth2.
type twitchProvider struct {
	*goauth.OAuth2Config
}

// newTwitchProvider creates new twitchProvider provider instance with some defaults.
func newTwitchProvider() goauth.Provider {
	return &twitchProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "twitchProvider",
		Pkce:        true,
		Scopes:      []string{"user:read:email"},
		AuthUrl:     twitch.Endpoint.AuthURL,
		TokenUrl:    twitch.Endpoint.TokenURL,
		UserApiUrl:  "https://api.twitch.tv/helix/users",
	}}
}

// FetchUser returns a Credential instance based the twitchProvider's user api.
// API reference: https://dev.twitch.tv/docs/api/reference#get-users
func (t *twitchProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := t.FetchRawData(token)
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

// FetchRawData implements provider.FetchRawData interface.
// This differs from oAuth2Provider because twitchProvider requires the `Client-Id` header.
func (t *twitchProvider) FetchRawData(token *oauth2.Token) ([]byte, error) {
	req, err := http.NewRequest("GET", t.GetUserApiUrl(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Client-Id", t.GetClientId())

	return t.SendRawUserDataRequest(req, token)
}
