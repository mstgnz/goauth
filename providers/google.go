package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
)

// googleProvider allows authentication via googleProvider OAuth2.
type googleProvider struct {
	*goauth.OAuth2Config
}

// newGoogleProvider creates new googleProvider provider instance with some defaults.
func newGoogleProvider() goauth.Provider {
	return &googleProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "googleProvider",
		AuthUrl:     "https://accounts.google.com/o/oauth2/auth",
		TokenUrl:    "https://accounts.google.com/o/oauth2/token",
		UserApiUrl:  "https://www.googleapis.com/oauth2/v1/userinfo",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based the googleProvider's user api.
func (g *googleProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := g.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		Picture       string `json:"picture"`
		VerifiedEmail bool   `json:"verified_email"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		AvatarUrl:    extracted.Picture,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.VerifiedEmail {
		user.Email = extracted.Email
	}

	return user, nil
}
