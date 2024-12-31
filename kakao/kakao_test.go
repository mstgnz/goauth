package kakao

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/kakao"
)

func TestNewKakaoProvider_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		wantName      string
		wantAuthURL   string
		wantTokenURL  string
		wantUserURL   string
		wantScopesLen int
		wantPkce      bool
	}{
		{
			name:          "Default provider creation",
			wantName:      "Kakao",
			wantAuthURL:   kakao.Endpoint.AuthURL,
			wantTokenURL:  kakao.Endpoint.TokenURL,
			wantUserURL:   "https://kapi.kakao.com/v2/user/me",
			wantScopesLen: 3,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewKakaoProvider()
			kakaoProvider, ok := provider.(*kakaoProvider)

			if !ok {
				t.Error("NewKakaoProvider should return *kakaoProvider type")
			}

			if kakaoProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", kakaoProvider.DisplayName, tt.wantName)
			}

			if kakaoProvider.AuthUrl != tt.wantAuthURL {
				t.Errorf("AuthUrl = %v, want %v", kakaoProvider.AuthUrl, tt.wantAuthURL)
			}

			if kakaoProvider.TokenUrl != tt.wantTokenURL {
				t.Errorf("TokenUrl = %v, want %v", kakaoProvider.TokenUrl, tt.wantTokenURL)
			}

			if kakaoProvider.UserApiUrl != tt.wantUserURL {
				t.Errorf("UserApiUrl = %v, want %v", kakaoProvider.UserApiUrl, tt.wantUserURL)
			}

			if len(kakaoProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(kakaoProvider.Scopes), tt.wantScopesLen)
			}

			if kakaoProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", kakaoProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{"profile_nickname", "profile_image", "account_email"}
			for i, scope := range kakaoProvider.Scopes {
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
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty client secret",
			clientID:     "test-id",
			clientSecret: "",
			redirectURL:  "http://localhost:8080/callback",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
		},
		{
			name:         "Empty redirect URL",
			clientID:     "test-id",
			clientSecret: "test-secret",
			redirectURL:  "",
			wantErr:      true,
			expectedErr:  "client id, client secret and redirect url are required",
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
			provider := NewKakaoProvider()
			kakaoProvider := provider.(*kakaoProvider)
			kakaoProvider.clientId = tt.clientID
			kakaoProvider.clientSecret = tt.clientSecret
			kakaoProvider.redirectUrl = tt.redirectURL

			err := kakaoProvider.ValidateConfig()
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
	mockUserData := map[string]interface{}{
		"id": 123456789,
		"properties": map[string]interface{}{
			"nickname":      "Test User",
			"profile_image": "https://example.com/avatar.jpg",
		},
		"kakao_account": map[string]interface{}{
			"email":             "test@example.com",
			"is_email_valid":    true,
			"is_email_verified": true,
		},
	}

	tests := []struct {
		name           string
		token          *oauth2.Token
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
		expectedUser   *goauth.Credential
	}{
		{
			name: "Valid user data",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse:   mockUserData,
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &goauth.Credential{
				Id:           "123456789",
				Username:     "Test User",
				Email:        "test@example.com",
				AvatarUrl:    "https://example.com/avatar.jpg",
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
			mockResponse: map[string]interface{}{
				"msg":  "Invalid access token",
				"code": -401,
			},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedUser:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Kakao API gereksinimlerini kontrol et
				if r.Header.Get("Authorization") == "" {
					t.Error("Authorization header is required")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				json.NewEncoder(w).Encode(tt.mockResponse)
			}))
			defer server.Close()

			provider := NewKakaoProvider()
			kakaoProvider := provider.(*kakaoProvider)
			kakaoProvider.UserApiUrl = server.URL

			user, err := kakaoProvider.FetchUser(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("FetchUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.expectedUser != nil {
				if user.Id != tt.expectedUser.Id {
					t.Errorf("User.Id = %v, want %v", user.Id, tt.expectedUser.Id)
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
		"access_token": "new-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	mockErrorResponse := map[string]interface{}{
		"error":             "invalid_grant",
		"error_description": "The refresh token is invalid",
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
			mockResponse:   mockErrorResponse,
			mockStatusCode: http.StatusBadRequest,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Kakao OAuth2 token endpoint gereksinimlerini kontrol et
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("Content-Type header should be application/x-www-form-urlencoded")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			provider := NewKakaoProvider()
			kakaoProvider := provider.(*kakaoProvider)
			kakaoProvider.tokenUrl = server.URL
			kakaoProvider.clientId = tt.clientID
			kakaoProvider.clientSecret = tt.clientSecret

			newToken, err := kakaoProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && newToken != nil {
				if newToken.AccessToken != mockTokenResponse["access_token"] {
					t.Errorf("AccessToken = %v, want %v", newToken.AccessToken, mockTokenResponse["access_token"])
				}
				if newToken.TokenType != mockTokenResponse["token_type"] {
					t.Errorf("TokenType = %v, want %v", newToken.TokenType, mockTokenResponse["token_type"])
				}
			}
		})
	}
}
