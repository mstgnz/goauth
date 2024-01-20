package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
)

// livechatProvider allows authentication via livechatProvider OAuth2.
type livechatProvider struct {
	*goauth.OAuth2Config
}

// newLivechatProvider creates new livechatProvider provider instance with some defaults.
func newLivechatProvider() goauth.Provider {
	return &livechatProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "LiveChat",
		AuthUrl:     "https://accounts.livechat.com/",
		TokenUrl:    "https://accounts.livechat.com/token",
		UserApiUrl:  "https://accounts.livechat.com/v2/accounts/me",
		Scopes:      []string{}, // default scopes are specified from the provider dashboard
		Pkce:        true,
	}}
}

// FetchUser returns a Credential based on the livechatProvider accounts API.
// API reference: https://developers.livechat.com/docs/authorization
func (l *livechatProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := l.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"account_id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		AvatarUrl     string `json:"avatar_url"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		AvatarUrl:    extracted.AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.EmailVerified {
		user.Email = extracted.Email
	}

	return user, nil
}
