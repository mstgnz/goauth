package vk

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"
)

type vkProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewVkProvider() goauth.Provider {
	return &vkProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "VK",
			AuthUrl:     vk.Endpoint.AuthURL,
			TokenUrl:    vk.Endpoint.TokenURL,
			UserApiUrl:  "https://api.vk.com/method/users.get",
			Scopes:      []string{"email"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *vkProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Response []struct {
			Id        int    `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Photo     string `json:"photo_200"`
			Email     string `json:"email"`
		} `json:"response"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	if len(extracted.Response) == 0 {
		return nil, errors.New("no user data returned from VK")
	}

	userData := extracted.Response[0]
	user := &goauth.Credential{
		Id:           strconv.Itoa(userData.Id),
		Name:         userData.FirstName + " " + userData.LastName,
		Email:        userData.Email,
		AvatarUrl:    userData.Photo,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *vkProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *vkProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL:  p.GetTokenUrl(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	return config.TokenSource(p.GetContext(), token).Token()
}
