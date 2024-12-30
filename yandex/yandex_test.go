package yandex

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yandex"
)

func TestNewYandexProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		wantName      string
		wantAuthUrl   string
		wantTokenUrl  string
		wantUserApi   string
		wantScopesLen int
		wantPkce      bool
	}{
		{
			name:          "Default provider creation",
			wantName:      "yandexProvider",
			wantAuthUrl:   yandex.Endpoint.AuthURL,
			wantTokenUrl:  yandex.Endpoint.TokenURL,
			wantUserApi:   "https://login.yandex.ru/info",
			wantScopesLen: 3,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewYandexProvider()
			yProvider, ok := provider.(*yandexProvider)

			if !ok {
				t.Error("NewYandexProvider should return *yandexProvider type")
			}

			if yProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", yProvider.DisplayName, tt.wantName)
			}

			if yProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", yProvider.AuthUrl, tt.wantAuthUrl)
			}

			if yProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", yProvider.TokenUrl, tt.wantTokenUrl)
			}

			if yProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", yProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(yProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(yProvider.Scopes), tt.wantScopesLen)
			}

			if yProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", yProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"login:email", "login:avatar", "login:info"}
			for i, scope := range yProvider.Scopes {
				if scope != expectedScopes[i] {
					t.Errorf("Scope[%d] = %v, want %v", i, scope, expectedScopes[i])
				}
			}
		})
	}
}

func TestValidateConfig_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		redirectURL  string
		wantErr      bool
		expectedErr  string
	}{
		{
			name:         "Empty client ID",
			clientID:     "",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client ID is required",
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client secret is required",
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			wantErr:      true,
			expectedErr:  "redirect URL is required",
		},
		{
			name:         "Valid configuration",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      false,
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewYandexProvider()
			yProvider := provider.(*yandexProvider)
			yProvider.OAuth2Config.ClientId = tt.clientID
			yProvider.OAuth2Config.ClientSecret = tt.clientSecret
			yProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := yProvider.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.expectedErr {
				t.Errorf("ValidateConfig() error = %v, want %v", err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestFetchUser_WithMockServer(t *testing.T) {
	// Mock Yandex user data
	mockUserData := map[string]interface{}{
		"id":                "123456789",
		"real_name":         "Test User",
		"login":             "testuser",
		"default_email":     "test@yandex.ru",
		"is_avatar_empty":   false,
		"default_avatar_id": "abc123",
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
		expectedUser   *config.Credential
	}{
		{
			name: "Valid user data with avatar",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse:   mockUserData,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "test@yandex.ru",
				AvatarUrl:    "https://avatars.yandex.net/get-yapic/abc123/islands-200",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "User without avatar",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse: map[string]interface{}{
				"id":              "123456789",
				"real_name":       "Test User",
				"login":           "testuser",
				"default_email":   "test@yandex.ru",
				"is_avatar_empty": true,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Username:     "testuser",
				Email:        "test@yandex.ru",
				AvatarUrl:    "",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "Invalid response format",
			token: &oauth2.Token{
				AccessToken: "invalid-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockResponse:   "invalid json",
			mockStatusCode: http.StatusOK,
			wantErr:        true,
			expectedUser:   nil,
		},
		{
			name: "API error response",
			token: &oauth2.Token{
				AccessToken: "error-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(time.Hour),
			},
			mockResponse:   map[string]interface{}{"error": "Invalid token"},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewYandexProvider()
			yProvider := provider.(*yandexProvider)
			yProvider.UserApiUrl = server.URL

			user, err := yProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.expectedUser != nil {
				if user.Id != tt.expectedUser.Id {
					t.Errorf("User.Id = %v, want %v", user.Id, tt.expectedUser.Id)
				}
				if user.Name != tt.expectedUser.Name {
					t.Errorf("User.Name = %v, want %v", user.Name, tt.expectedUser.Name)
				}
				if user.Username != tt.expectedUser.Username {
					t.Errorf("User.Username = %v, want %v", user.Username, tt.expectedUser.Username)
				}
				if user.Email != tt.expectedUser.Email {
					t.Errorf("User.Email = %v, want %v", user.Email, tt.expectedUser.Email)
				}
				if user.AvatarUrl != tt.expectedUser.AvatarUrl {
					t.Errorf("User.AvatarUrl = %v, want %v", user.AvatarUrl, tt.expectedUser.AvatarUrl)
				}
				if user.AccessToken != tt.expectedUser.AccessToken {
					t.Errorf("User.AccessToken = %v, want %v", user.AccessToken, tt.expectedUser.AccessToken)
				}
				if user.RefreshToken != tt.expectedUser.RefreshToken {
					t.Errorf("User.RefreshToken = %v, want %v", user.RefreshToken, tt.expectedUser.RefreshToken)
				}
			}
		})
	}
}

func TestRefreshToken_WithMockServer(t *testing.T) {
	mockTokenResponse := map[string]interface{}{
		"access_token":  "new-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "new-refresh-token",
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		clientID       string
		clientSecret   string
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
	}{
		{
			name: "Valid refresh token",
			token: &oauth2.Token{
				AccessToken:  "old-access-token",
				TokenType:    "Bearer",
				RefreshToken: "old-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   mockTokenResponse,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
		},
		{
			name: "Empty refresh token",
			token: &oauth2.Token{
				AccessToken: "old-access-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   nil,
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
		{
			name: "Invalid refresh token",
			token: &oauth2.Token{
				AccessToken:  "old-access-token",
				TokenType:    "Bearer",
				RefreshToken: "invalid-refresh-token",
				Expiry:       time.Now().Add(-time.Hour),
			},
			clientID:       "test-client-id",
			clientSecret:   "test-client-secret",
			mockResponse:   map[string]interface{}{"error": "invalid_grant"},
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			provider := NewYandexProvider()
			yProvider := provider.(*yandexProvider)
			yProvider.TokenUrl = server.URL
			yProvider.OAuth2Config.ClientId = tt.clientID
			yProvider.OAuth2Config.ClientSecret = tt.clientSecret

			newToken, err := yProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && newToken != nil {
				if newToken.AccessToken != mockTokenResponse["access_token"] {
					t.Errorf("AccessToken = %v, want %v", newToken.AccessToken, mockTokenResponse["access_token"])
				}
				if newToken.RefreshToken != mockTokenResponse["refresh_token"] {
					t.Errorf("RefreshToken = %v, want %v", newToken.RefreshToken, mockTokenResponse["refresh_token"])
				}
			}
		})
	}
}
