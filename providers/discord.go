package goauth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
)

// discordProvider allows authentication via discordProvider OAuth2.
type discordProvider struct {
	*goauth.OAuth2Config
}

// newDiscordProvider creates a new discordProvider provider instance with some defaults.
func newDiscordProvider() goauth.Provider {
	// https://discord.com/developers/docs/topics/oauth2
	// https://discord.com/developers/docs/resources/user#get-current-user
	return &discordProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "discordProvider",
		AuthUrl:     "https://discord.com/api/oauth2/authorize",
		TokenUrl:    "https://discord.com/api/oauth2/token",
		UserApiUrl:  "https://discord.com/api/users/@me",
		Scopes:      []string{"identify", "email"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance from discordProvider's user api.
// API reference:  https://discord.com/developers/docs/resources/user#user-object
func (d *discordProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := d.FetchRawData(token)
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

	user := &goauth.Credential{
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
