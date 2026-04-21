package kakao

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/kakao"
)

// kakaoProvider allows authentication via kakaoProvider OAuth2.
type kakaoProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
}

// NewKakaoProvider creates a new kakaoProvider provider instance with some defaults.
func NewKakaoProvider() goauth.Provider {
	return &kakaoProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Kakao",
			AuthUrl:     kakao.Endpoint.AuthURL,
			TokenUrl:    kakao.Endpoint.TokenURL,
			UserApiUrl:  "https://kapi.kakao.com/v2/user/me",
			Scopes:      []string{"profile_nickname", "profile_image", "account_email"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
	}
}

// FetchUser returns a Credential instance based on the kakaoProvider user api.
// API reference: https://developers.kakao.com/docs/latest/en/kakaologin/rest-api#req-user-info-response
func (p *kakaoProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id      int `json:"id"`
		Profile struct {
			Nickname string `json:"nickname"`
			ImageUrl string `json:"profile_image"`
		} `json:"properties"`
		KakaoAccount struct {
			Email           string `json:"email"`
			IsEmailVerified bool   `json:"is_email_verified"`
			IsEmailValid    bool   `json:"is_email_valid"`
		} `json:"kakao_account"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           strconv.Itoa(extracted.Id),
		Username:     extracted.Profile.Nickname,
		AvatarUrl:    extracted.Profile.ImageUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	if extracted.KakaoAccount.IsEmailValid && extracted.KakaoAccount.IsEmailVerified {
		user.Email = extracted.KakaoAccount.Email
	}

	return user, nil
}

func (p *kakaoProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

func (p *kakaoProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
