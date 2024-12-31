package kakao

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mstgnz/goauth"
	"github.com/mstgnz/goauth/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/kakao"
)

// kakaoProvider allows authentication via kakaoProvider OAuth2.
type kakaoProvider struct {
	*config.OAuth2Config
	clientId     string
	clientSecret string
	redirectUrl  string
	tokenUrl     string
}

// NewKakaoProvider creates a new kakaoProvider provider instance with some defaults.
func NewKakaoProvider() goauth.Provider {
	oauth2Config := &config.OAuth2Config{
		Ctx:          context.Background(),
		DisplayName:  "Kakao",
		ClientId:     "",
		ClientSecret: "",
		RedirectUrl:  "",
		AuthUrl:      kakao.Endpoint.AuthURL,
		TokenUrl:     kakao.Endpoint.TokenURL,
		UserApiUrl:   "https://kapi.kakao.com/v2/user/me",
		Scopes:       []string{"profile_nickname", "profile_image", "account_email"},
		Pkce:         true,
	}

	return &kakaoProvider{
		OAuth2Config: oauth2Config,
		clientId:     oauth2Config.ClientId,
		clientSecret: oauth2Config.ClientSecret,
		redirectUrl:  oauth2Config.RedirectUrl,
		tokenUrl:     oauth2Config.TokenUrl,
	}
}

// FetchUser returns a Credential instance based on the kakaoProvider user api.
// API reference: https://developers.kakao.com/docs/latest/en/kakaologin/rest-api#req-user-info-response
func (p *kakaoProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
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

	user := &config.Credential{
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

func (p *kakaoProvider) ValidateConfig() error {
	if p.clientId == "" || p.clientSecret == "" || p.redirectUrl == "" {
		return errors.New("client id, client secret and redirect url are required")
	}
	return nil
}

func (p *kakaoProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", token.RefreshToken)
	data.Set("client_id", p.clientId)
	data.Set("client_secret", p.clientSecret)

	req, err := http.NewRequest("POST", p.tokenUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return nil, err
		}
		return nil, errors.New(errorResponse.ErrorDescription)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
		Expiry:      time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}, nil
}
