package google

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth/config"
	"golang.org/x/oauth2"
)

func TestNewGoogleProvider_TableDriven(t *testing.T) {
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
			wantName:      "googleProvider",
			wantAuthUrl:   "https://accounts.google.com/o/oauth2/auth",
			wantTokenUrl:  "https://accounts.google.com/o/oauth2/token",
			wantUserApi:   "https://www.googleapis.com/oauth2/v1/userinfo",
			wantScopesLen: 2,
			wantPkce:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewGoogleProvider()
			gProvider, ok := provider.(*googleProvider)

			if !ok {
				t.Error("NewGoogleProvider should return *googleProvider type")
			}

			if gProvider.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %v, want %v", gProvider.DisplayName, tt.wantName)
			}

			if gProvider.AuthUrl != tt.wantAuthUrl {
				t.Errorf("AuthUrl = %v, want %v", gProvider.AuthUrl, tt.wantAuthUrl)
			}

			if gProvider.TokenUrl != tt.wantTokenUrl {
				t.Errorf("TokenUrl = %v, want %v", gProvider.TokenUrl, tt.wantTokenUrl)
			}

			if gProvider.UserApiUrl != tt.wantUserApi {
				t.Errorf("UserApiUrl = %v, want %v", gProvider.UserApiUrl, tt.wantUserApi)
			}

			if len(gProvider.Scopes) != tt.wantScopesLen {
				t.Errorf("Scopes length = %v, want %v", len(gProvider.Scopes), tt.wantScopesLen)
			}

			if gProvider.Pkce != tt.wantPkce {
				t.Errorf("Pkce = %v, want %v", gProvider.Pkce, tt.wantPkce)
			}

			// Scopes içeriğini kontrol et
			expectedScopes := []string{
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/userinfo.email",
			}
			for i, scope := range gProvider.Scopes {
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
			provider := NewGoogleProvider()
			gProvider := provider.(*googleProvider)
			gProvider.OAuth2Config.ClientId = tt.clientID
			gProvider.OAuth2Config.ClientSecret = tt.clientSecret
			gProvider.OAuth2Config.RedirectUrl = tt.redirectURL

			err := gProvider.ValidateConfig()
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
	// Mock Google user data
	mockUserData := map[string]interface{}{
		"id":             "123456789",
		"name":           "Test User",
		"email":          "test@gmail.com",
		"picture":        "https://lh3.googleusercontent.com/test/photo.jpg",
		"verified_email": true,
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
			name: "Valid user data with verified email",
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
				Email:        "test@gmail.com",
				AvatarUrl:    "https://lh3.googleusercontent.com/test/photo.jpg",
				AccessToken:  "valid-token",
				RefreshToken: "refresh-token",
			},
		},
		{
			name: "User with unverified email",
			token: &oauth2.Token{
				AccessToken:  "valid-token",
				TokenType:    "Bearer",
				Expiry:       time.Now().Add(time.Hour),
				RefreshToken: "refresh-token",
			},
			mockResponse: map[string]interface{}{
				"id":             "123456789",
				"name":           "Test User",
				"email":          "test@gmail.com",
				"picture":        "https://lh3.googleusercontent.com/test/photo.jpg",
				"verified_email": false,
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			expectedUser: &config.Credential{
				Id:           "123456789",
				Name:         "Test User",
				Email:        "",
				AvatarUrl:    "https://lh3.googleusercontent.com/test/photo.jpg",
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

			provider := NewGoogleProvider()
			gProvider := provider.(*googleProvider)
			gProvider.UserApiUrl = server.URL

			user, err := gProvider.FetchUser(tt.token)
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
	tests := []struct {
		name         string
		token        *oauth2.Token
		clientID     string
		clientSecret string
		wantErr      bool
	}{
		{
			name: "Empty refresh token",
			token: &oauth2.Token{
				AccessToken: "old-access-token",
				TokenType:   "Bearer",
				Expiry:      time.Now().Add(-time.Hour),
			},
			clientID:     "test-client-id",
			clientSecret: "test-client-secret",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewGoogleProvider()
			gProvider := provider.(*googleProvider)
			gProvider.OAuth2Config.ClientId = tt.clientID
			gProvider.OAuth2Config.ClientSecret = tt.clientSecret

			_, err := gProvider.RefreshToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err == nil {
				t.Error("RefreshToken() expected error but got nil")
			}
		})
	}
}

func TestRefreshToken_EmptyToken(t *testing.T) {
	provider := NewGoogleProvider()
	token := &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-time.Hour),
	}

	_, err := provider.RefreshToken(token)
	if err == nil {
		t.Error("RefreshToken() should return error when refresh token is empty")
	}

	expectedError := "refresh token is required"
	if err.Error() != expectedError {
		t.Errorf("RefreshToken() error = %v, want %v", err.Error(), expectedError)
	}
}
