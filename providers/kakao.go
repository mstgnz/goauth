package goauth

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/kakao"
)

// kakaoProvider allows authentication via kakaoProvider OAuth2.
type kakaoProvider struct {
	*goauth.OAuth2Config
}

// newKakaoProvider creates a new kakaoProvider provider instance with some defaults.
func newKakaoProvider() goauth.Provider {
	return &kakaoProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "kakaoProvider",
		AuthUrl:     kakao.Endpoint.AuthURL,
		TokenUrl:    kakao.Endpoint.TokenURL,
		UserApiUrl:  "https://kapi.kakao.com/v2/user/me",
		Scopes:      []string{"account_email", "profile_nickname", "profile_image"},
		Pkce:        true,
	}}
}

// FetchUser returns a Credential instance based on the kakaoProvider user api.
// API reference: https://developers.kakao.com/docs/latest/en/kakaologin/rest-api#req-user-info-response
func (k *kakaoProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := k.FetchRawData(token)
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
	}

	if extracted.KakaoAccount.IsEmailValid && extracted.KakaoAccount.IsEmailVerified {
		user.Email = extracted.KakaoAccount.Email
	}

	return user, nil
}
