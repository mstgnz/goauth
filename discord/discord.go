package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"
	"golang.org/x/oauth2"
)

// discordProvider allows authentication via Discord OAuth2.
type discordProvider struct {
	*config.OAuth2Config
	provider.BaseProvider
}

// NewDiscordProvider creates new Discord provider instance with some defaults.
func NewDiscordProvider() provider.Provider {
	return &discordProvider{
		OAuth2Config: &config.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Discord",
			AuthUrl:     "https://discord.com/api/oauth2/authorize",
			TokenUrl:    "https://discord.com/api/oauth2/token",
			UserApiUrl:  "https://discord.com/api/users/@me",
			Scopes:      []string{"identify", "email"},
			Pkce:        true,
		},
		BaseProvider: provider.BaseProvider{},
	}
}

// ValidateConfig validates the provider configuration.
func (p *discordProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *discordProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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

// FetchUser returns a Credential instance from discordProvider's user api.
// API reference:  https://discord.com/developers/docs/resources/user#user-object
func (p *discordProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"id"`
		Username      string `json:"username"`
		Discriminator string `json:"discriminator"`
		Avatar        string `json:"avatar"`
		Email         string `json:"email"`
		Verified      bool   `json:"verified"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	// Build a full avatar URL using the avatar hash provided in the API response
	// https://discord.com/developers/docs/reference#image-formatting
	avatarUrl := fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", extracted.Id, extracted.Avatar)

	// Concatenate the user's username and discriminator into a single username string
	username := fmt.Sprintf("%s#%s", extracted.Username, extracted.Discriminator)

	user := &config.Credential{
		Id:           extracted.Id,
		Name:         username,
		Username:     extracted.Username,
		AvatarUrl:    avatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.Verified {
		user.Email = extracted.Email
	}

	return user, nil
}
