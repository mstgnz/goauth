package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

// yandexProvider allows authentication via yandexProvider OAuth2.
type yandexProvider struct {
	*goauth.OAuth2Config
}

// newYandexProvider creates new yandexProvider provider instance with some defaults.
// Docs: https://yandex.ru/dev/id/doc/en/
func newYandexProvider() goauth.Provider {
	return &yandexProvider{&goauth.OAuth2Config{
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
func (y *yandexProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := y.FetchRawData(token)
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

	user := &goauth.Credential{
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
