package spotify

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
)

// spotifyProvider allows authentication via Spotify OAuth2.
type spotifyProvider struct {
	*config.OAuth2Config
	provider.BaseProvider
}

// NewSpotifyProvider creates new Spotify provider instance with some defaults.
func NewSpotifyProvider() provider.Provider {
	return &spotifyProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Spotify",
			AuthUrl:     "https://accounts.spotify.com/authorize",
			TokenUrl:    "https://accounts.spotify.com/api/token",
			UserApiUrl:  "https://api.spotify.com/v1/me",
			Scopes:      []string{"user-read-email", "user-read-private"},
			Pkce:        true,
		},
		BaseProvider: provider.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *spotifyProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *spotifyProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL: p.GetTokenUrl(),
		},
	}

	return config.TokenSource(p.GetContext(), token).Token()
}

// FetchUser returns a Credential instance based on the spotifyProvider's user api.
// API reference: https://developer.spotify.com/documentation/web-api/reference/#/operations/get-current-users-profile
func (p *spotifyProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
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

	user := &config.Credential{
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
