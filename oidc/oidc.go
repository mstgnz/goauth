package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mstgnz/goauth/config"
	"github.com/mstgnz/goauth/provider"

	"golang.org/x/oauth2"
)

type oidcProvider struct {
	*config.OAuth2Config
	clientId     string
	clientSecret string
	redirectUrl  string
	tokenUrl     string
}

func NewOidcProvider() provider.Provider {
	oauth2Config := &config.OAuth2Config{
		Ctx:          context.Background(),
		DisplayName:  "OpenID Connect",
		ClientId:     "",
		ClientSecret: "",
		RedirectUrl:  "",
		AuthUrl:      "",
		TokenUrl:     "",
		UserApiUrl:   "",
		Scopes:       []string{"openid", "profile", "email"},
		Pkce:         true,
	}

	return &oidcProvider{
		OAuth2Config: oauth2Config,
		clientId:     oauth2Config.ClientId,
		clientSecret: oauth2Config.ClientSecret,
		redirectUrl:  oauth2Config.RedirectUrl,
		tokenUrl:     oauth2Config.TokenUrl,
	}
}

func (p *oidcProvider) FetchUser(token *oauth2.Token) (*config.Credential, error) {
	data, err := p.OAuth2Config.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	var response struct {
		Sub      string `json:"sub"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		Picture  string `json:"picture"`
		Username string `json:"preferred_username"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	user := &config.Credential{
		Id:        response.Sub,
		Name:      response.Name,
		Email:     response.Email,
		Username:  response.Username,
		AvatarUrl: response.Picture,
	}

	return user, nil
}

func (p *oidcProvider) ValidateConfig() error {
	if p.clientId == "" || p.clientSecret == "" || p.redirectUrl == "" {
		return errors.New("client id, client secret and redirect url are required")
	}
	if p.AuthUrl == "" || p.TokenUrl == "" || p.UserApiUrl == "" {
		return errors.New("auth url, token url and user api url are required")
	}
	return nil
}

func (p *oidcProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
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
			return nil, errors.New("failed to refresh token")
		}
		return nil, fmt.Errorf("%s: %s", errorResponse.Error, errorResponse.ErrorDescription)
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
