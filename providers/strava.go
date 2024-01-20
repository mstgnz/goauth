package goauth

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// stravaProvider allows authentication via stravaProvider OAuth2.
type stravaProvider struct {
	*goauth.OAuth2Config
}

// newStravaProvider creates new stravaProvider provider instance with some defaults.
func newStravaProvider() goauth.Provider {
	return &stravaProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "stravaProvider",
		AuthUrl:     "https://www.strava.com/oauth/authorize",
		TokenUrl:    "https://www.strava.com/api/v3/oauth/token",
		UserApiUrl:  "https://www.strava.com/api/v3/athlete",
		Scopes: []string{
			"profile:read_all",
		},
		Pkce: true,
	}}
}

// FetchUser returns a Credential instance based on the stravaProvider's user api.
// API reference: https://developers.strava.com/docs/authentication/
func (s *stravaProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := s.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id              int    `json:"id"`
		FirstName       string `json:"firstname"`
		LastName        string `json:"lastname"`
		Username        string `json:"username"`
		ProfileImageUrl string `json:"profile"`

		// At the time of writing, stravaProvider OAuth2 doesn't support returning the user email address
		// Email string `json:"email"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Name:         extracted.FirstName + " " + extracted.LastName,
		Username:     extracted.Username,
		AvatarUrl:    extracted.ProfileImageUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.Id != 0 {
		user.Id = strconv.Itoa(extracted.Id)
	}

	return user, nil
}
