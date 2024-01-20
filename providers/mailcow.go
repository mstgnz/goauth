package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
)

// mailcowProvider allows authentication via mailcowProvider OAuth2.
type mailcowProvider struct {
	*goauth.OAuth2Config
}

// newMailcowProvider creates a new mailcowProvider provider instance with some defaults.
func newMailcowProvider() goauth.Provider {
	return &mailcowProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "mailcowProvider",
		Scopes:      []string{"profile"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on mailcowProvider user api.
// API reference: https://github.com/mailcow/mailcow-dockerized/blob/master/data/web/oauth/profile.php
func (m *mailcowProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := m.FetchRawData(token)
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
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Active   int    `json:"active"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	if extracted.Active != 1 {
		return nil, errors.New("the mailcowProvider user is not active")
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.FullName,
		Username:     extracted.Username,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	// mailcowProvider usernames are usually just the email addresses, so we just take the part in front of the @
	if strings.Contains(user.Username, "@") {
		user.Username = strings.Split(user.Username, "@")[0]
	}

	return user, nil
}
