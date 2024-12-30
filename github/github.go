package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// gitHubProvider allows authentication via gitHubProvider OAuth2.
type gitHubProvider struct {
	*config.OAuth2Config
}

// NewGithubProvider creates new gitHubProvider provider instance with some defaults.
func NewGithubProvider() provider.Provider {
	return &gitHubProvider{&config.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "GitHub",
		AuthUrl:     github.Endpoint.AuthURL,
		TokenUrl:    github.Endpoint.TokenURL,
		UserApiUrl:  "https://api.github.com/user",
		Scopes:      []string{"read:user", "user:email"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based the gitHubProvider's user api.
// API reference: https://docs.github.com/en/rest/reference/users#get-the-authenticated-user
func (p *gitHubProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Login     string `json:"login"`
		Id        int    `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarUrl string `json:"avatar_url"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:           strconv.Itoa(extracted.Id),
		Name:         extracted.Name,
		Username:     extracted.Login,
		Email:        extracted.Email,
		AvatarUrl:    extracted.AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	// in case user has set "Keep my email address private", send an
	// **optional** API request to retrieve the verified primary email
	if user.Email == "" {
		email, err := p.fetchPrimaryEmail(token)
		if err != nil {
			return nil, err
		}
		user.Email = email
	}

	return user, nil
}

// fetchPrimaryEmail sends an API request to retrieve the verified
// primary email, in case "Keep my email address private" was set.
// NB! This method can succeed and still return an empty email.
// Error responses that are result of insufficient scopes permissions are ignored.
// API reference: https://docs.github.com/en/rest/users/emails?apiVersion=2022-11-28
func (p *gitHubProvider) fetchPrimaryEmail(token *oauth2.Token) (string, error) {
	client := p.Client(token)

	response, err := client.Get(p.GetUserApiUrl() + "/emails")
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	// ignore common http errors caused by insufficient scope permissions
	// (the email field is optional, aka. return the auth user without it)
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 {
		return "", nil
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string
		Verified bool
		Primary  bool
	}
	if err = json.Unmarshal(content, &emails); err != nil {
		return "", err
	}

	// extract the verified primary email
	for _, email := range emails {
		if email.Verified && email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *gitHubProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	// GitHub does not support refresh tokens
	return nil, errors.New("GitHub does not support refresh tokens")
}

// ValidateConfig validates the provider configuration.
func (p *gitHubProvider) ValidateConfig() error {
	if p.GetClientId() == "" {
		return errors.New("client ID is required")
	}
	if p.GetClientSecret() == "" {
		return errors.New("client secret is required")
	}
	if p.GetRedirectUrl() == "" {
		return errors.New("redirect URL is required")
	}
	return nil
}
