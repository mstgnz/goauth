package strava

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
)

type stravaProvider struct {
	*config.OAuth2Config
	clientId     string
	clientSecret string
	redirectUrl  string
	tokenUrl     string
}

func NewStravaProvider() provider.Provider {
	oauth2Config := &config.OAuth2Config{
		Ctx:          context.Background(),
		DisplayName:  "Strava",
		ClientId:     "",
		ClientSecret: "",
		RedirectUrl:  "",
		AuthUrl:      "https://www.strava.com/oauth/authorize",
		TokenUrl:     "https://www.strava.com/oauth/token",
		UserApiUrl:   "https://www.strava.com/api/v3/athlete",
		Scopes:       []string{"read", "profile:read_all"},
		Pkce:         true,
	}

	return &stravaProvider{
		OAuth2Config: oauth2Config,
		clientId:     oauth2Config.ClientId,
		clientSecret: oauth2Config.ClientSecret,
		redirectUrl:  oauth2Config.RedirectUrl,
		tokenUrl:     oauth2Config.TokenUrl,
	}
}

func (p *stravaProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	var response struct {
		Id        int    `json:"id"`
		FirstName string `json:"firstname"`
		LastName  string `json:"lastname"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		Profile   string `json:"profile"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:        strconv.Itoa(response.Id),
		Name:      response.FirstName + " " + response.LastName,
		Username:  response.Username,
		Email:     response.Email,
		AvatarUrl: response.Profile,
	}

	return user, nil
}

func (p *stravaProvider) ValidateConfig() error {
	if p.clientId == "" || p.clientSecret == "" || p.redirectUrl == "" {
		return errors.New("client id, client secret and redirect url are required")
	}
	return nil
}

func (p *stravaProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
