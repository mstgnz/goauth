package livechat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

func TestNewLiveChatProvider(t *testing.T) {
	provider := NewLiveChatProvider()
	if provider == nil {
		t.Error("Provider should not be nil")
	}
}

func TestLiveChatProvider_ValidateConfig(t *testing.T) {
	tests := []struct {
		name         string
		clientId     string
		clientSecret string
		redirectUrl  string
		expectError  bool
	}{
		{
			name:         "Valid config",
			clientId:     "test-client-id",
			clientSecret: "test-client-secret",
			redirectUrl:  "http://localhost/callback",
			expectError:  false,
		},
		{
			name:         "Missing client id",
			clientId:     "",
			clientSecret: "test-client-secret",
			redirectUrl:  "http://localhost/callback",
			expectError:  true,
		},
		{
			name:         "Missing client secret",
			clientId:     "test-client-id",
			clientSecret: "",
			redirectUrl:  "http://localhost/callback",
			expectError:  true,
		},
		{
			name:         "Missing redirect url",
			clientId:     "test-client-id",
			clientSecret: "test-client-secret",
			redirectUrl:  "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &livechatProvider{
				OAuth2Config: &config.OAuth2Config{
					ClientId:     tt.clientId,
					ClientSecret: tt.clientSecret,
					RedirectUrl:  tt.redirectUrl,
				},
				clientId:     tt.clientId,
				clientSecret: tt.clientSecret,
				redirectUrl:  tt.redirectUrl,
			}

			err := provider.ValidateConfig()
			if (err != nil) != tt.expectError {
				t.Errorf("ValidateConfig() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestLiveChatProvider_FetchUser(t *testing.T) {
	mockUser := struct {
		Id        string `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		Avatar    string `json:"avatar"`
		AccountId string `json:"account_id"`
	}{
		Id:        "123",
		Name:      "Test User",
		Email:     "test@example.com",
		Avatar:    "https://example.com/avatar.jpg",
		AccountId: "acc123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/accounts/me" {
			t.Errorf("Expected path '/v2/accounts/me', got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Expected Authorization header 'Bearer test-token', got %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(mockUser)
	}))
	defer server.Close()

	provider := &livechatProvider{
		OAuth2Config: &config.OAuth2Config{
			UserApiUrl: server.URL + "/v2/accounts/me",
			Ctx:        context.Background(),
		},
	}

	token := &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}

	user, err := provider.FetchUser(token)
	if err != nil {
		t.Fatalf("FetchUser() error = %v", err)
	}

	if user.Id != mockUser.Id {
		t.Errorf("Expected user ID %s, got %s", mockUser.Id, user.Id)
	}
	if user.Name != mockUser.Name {
		t.Errorf("Expected user name %s, got %s", mockUser.Name, user.Name)
	}
	if user.Email != mockUser.Email {
		t.Errorf("Expected user email %s, got %s", mockUser.Email, user.Email)
	}
	if user.AvatarUrl != mockUser.Avatar {
		t.Errorf("Expected user avatar %s, got %s", mockUser.Avatar, user.AvatarUrl)
	}
}

func TestLiveChatProvider_RefreshToken(t *testing.T) {
	mockResponse := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}{
		AccessToken: "new-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("Expected grant_type 'refresh_token', got %s", r.FormValue("grant_type"))
		}
		if r.FormValue("refresh_token") != "test-refresh-token" {
			t.Errorf("Expected refresh_token 'test-refresh-token', got %s", r.FormValue("refresh_token"))
		}
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	provider := &livechatProvider{
		OAuth2Config: &config.OAuth2Config{},
		clientId:     "test-client-id",
		clientSecret: "test-client-secret",
		tokenUrl:     server.URL,
	}

	oldToken := &oauth2.Token{
		RefreshToken: "test-refresh-token",
	}

	newToken, err := provider.RefreshToken(oldToken)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}

	if newToken.AccessToken != mockResponse.AccessToken {
		t.Errorf("Expected access token %s, got %s", mockResponse.AccessToken, newToken.AccessToken)
	}
	if newToken.TokenType != mockResponse.TokenType {
		t.Errorf("Expected token type %s, got %s", mockResponse.TokenType, newToken.TokenType)
	}
}
