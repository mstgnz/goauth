package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// facebookProvider allows authentication via facebookProvider OAuth2.
type facebookProvider struct {
	*goauth.OAuth2Config
}

// newFacebookProvider creates new facebookProvider provider instance with some defaults.
func newFacebookProvider() goauth.Provider {
	return &facebookProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "facebookProvider",
		AuthUrl:     facebook.Endpoint.AuthURL,
		TokenUrl:    facebook.Endpoint.TokenURL,
		UserApiUrl:  "https://graph.facebook.com/me?fields=name,email,picture.type(large)",
		Scopes:      []string{"email"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on the facebookProvider's user api.
// API reference: https://developers.facebook.com/docs/graph-api/reference/user/
func (f *facebookProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := f.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id      string
		Name    string
		Email   string
		Picture struct {
			Data struct{ Url string }
		}
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		AvatarUrl:    extracted.Picture.Data.Url,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
