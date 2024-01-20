package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
)

// spotifyProvider allows authentication via spotifyProvider OAuth2.
type spotifyProvider struct {
	*goauth.OAuth2Config
}

// newSpotifyProvider creates a new spotifyProvider provider instance with some defaults.
func newSpotifyProvider() goauth.Provider {
	return &spotifyProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "spotifyProvider",
		AuthUrl:     spotify.Endpoint.AuthURL,
		TokenUrl:    spotify.Endpoint.TokenURL,
		UserApiUrl:  "https://api.spotify.com/v1/me",
		Scopes: []string{
			"user-read-private",
			// currently spotifyProvider doesn't return information whether the email is verified or not
			// "user-read-email",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based on the spotifyProvider's user api.
// API reference: https://developer.spotify.com/documentation/web-api/reference/#/operations/get-current-users-profile
func (s *spotifyProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := s.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id     string `json:"id"`
		Name   string `json:"display_name"`
		Images []struct {
			Url string `json:"url"`
		} `json:"images"`
		// don't map the email because per the official docs
		// the email field is "unverified" and there is no proof
		// that it actually belongs to the user
		// Email  string `json:"email"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if len(extracted.Images) > 0 {
		user.AvatarUrl = extracted.Images[0].Url
	}

	return user, nil
}
