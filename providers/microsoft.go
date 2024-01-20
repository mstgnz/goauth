package goauth

import (
	"context"
	"encoding/json"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// microsoftProvider allows authentication via AzureADEndpoint OAuth2.
type microsoftProvider struct {
	*goauth.OAuth2Config
}

// newMicrosoftProvider creates new microsoftProvider AD provider instance with some defaults.
func newMicrosoftProvider() goauth.Provider {
	azure := microsoft.AzureADEndpoint("")
	return &microsoftProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "microsoftProvider",
		AuthUrl:     azure.AuthURL,
		TokenUrl:    azure.TokenURL,
		UserApiUrl:  "https://graph.microsoft.com/v1.0/me",
		Scopes:      []string{"User.Read"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on the microsoftProvider's user api.
// API reference:  https://learn.microsoft.com/en-us/azure/active-directory/develop/userinfo
// Graph explorer: https://developer.microsoft.com/en-us/graph/graph-explorer
func (p *microsoftProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id    string `json:"id"`
		Name  string `json:"displayName"`
		Email string `json:"mail"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	return user, nil
}
