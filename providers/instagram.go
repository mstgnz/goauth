package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/instagram"
)

// instagramProvider allows authentication via instagramProvider OAuth2.
type instagramProvider struct {
	*goauth.OAuth2Config
}

// newInstagramProvider creates new instagramProvider provider instance with some defaults.
func newInstagramProvider() goauth.Provider {
	return &instagramProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "instagramProvider",
		AuthUrl:     instagram.Endpoint.AuthURL,
		TokenUrl:    instagram.Endpoint.TokenURL,
		UserApiUrl:  "https://graph.instagram.com/me?fields=id,username,account_type",
		Scopes:      []string{"user_profile"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on the instagramProvider's user api.
// API reference: https://developers.facebook.com/docs/instagram-basic-display-api/reference/user#fields
func (i *instagramProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := i.FetchRawData(token)
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
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Username:     extracted.Username,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
