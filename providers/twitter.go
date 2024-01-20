package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// twitterProvider allows authentication via twitterProvider OAuth2.
type twitterProvider struct {
	*goauth.OAuth2Config
}

// newTwitterProvider creates new twitterProvider provider instance with some defaults.
func newTwitterProvider() goauth.Provider {
	return &twitterProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "twitterProvider",
		AuthUrl:     "https://twitter.com/i/oauth2/authorize",
		TokenUrl:    "https://api.twitter.com/2/oauth2/token",
		UserApiUrl:  "https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url",
		Scopes: []string{
			"users.read",

			// we don't actually use this scope, but for some reason it is required by the `/2/users/me` endpoint
			// (see https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me)
			"tweet.read",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based on the twitterProvider's user api.
// API reference: https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me
func (t *twitterProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := t.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Data struct {
			Id              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageUrl string `json:"profile_image_url"`

			// NB! At the time of writing, twitterProvider OAuth2 doesn't support returning the user email address
			// (see https://twittercommunity.com/t/which-api-to-get-user-after-oauth2-authorization/162417/33)
			// Email string `json:"email"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Data.Id,
		Name:         extracted.Data.Name,
		Username:     extracted.Data.Username,
		AvatarUrl:    extracted.Data.ProfileImageUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
