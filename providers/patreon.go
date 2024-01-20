package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

// patreonProvider allows authentication via patreonProvider OAuth2.
type patreonProvider struct {
	*goauth.OAuth2Config
}

// newPatreonProvider creates new patreonProvider provider instance with some defaults.
func newPatreonProvider() goauth.Provider {
	return &patreonProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "patreonProvider",
		AuthUrl:     "https://www.patreon.com/oauth2/authorize",
		TokenUrl:    "https://www.patreon.com/api/oauth2/token",
		UserApiUrl:  "https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=full_name,email,vanity,image_url,is_email_verified",
		Scopes:      []string{"identity", "identity[email]"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on the patreonProvider identity api.
// API reference:
// https://docs.patreon.com/#get-api-oauth2-v2-identity
// https://docs.patreon.com/#user-v2
func (p *patreonProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Data struct {
			Id         string `json:"id"`
			Attributes struct {
				Email           string `json:"email"`
				Name            string `json:"full_name"`
				Username        string `json:"vanity"`
				AvatarUrl       string `json:"image_url"`
				IsEmailVerified bool   `json:"is_email_verified"`
			} `json:"attributes"`
		} `json:"data"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Data.Id,
		Username:     extracted.Data.Attributes.Username,
		Name:         extracted.Data.Attributes.Name,
		AvatarUrl:    extracted.Data.Attributes.AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.Data.Attributes.IsEmailVerified {
		user.Email = extracted.Data.Attributes.Email
	}

	return user, nil
}
