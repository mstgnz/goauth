package livechat

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

type livechatProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

func NewLiveChatProvider() goauth.Provider {
	return &livechatProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "LiveChat",
			AuthUrl:     "https://accounts.livechat.com/oauth/authorize",
			TokenUrl:    "https://accounts.livechat.com/oauth/token",
			UserApiUrl:  "https://accounts.livechat.com/v2/accounts/me",
			Scopes:      []string{"accounts.read", "users.read"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

func (p *livechatProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
		Avatar string `json:"avatar"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		Name:         extracted.Name,
		Email:        extracted.Email,
		AvatarUrl:    extracted.Avatar,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	return user, nil
}

func (p *livechatProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *livechatProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
