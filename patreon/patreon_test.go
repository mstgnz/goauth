package patreon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mstgnz/goauth"
	"golang.org/x/oauth2"
)

func TestNewPatreonProvider(t *testing.T) {
	provider := NewPatreonProvider()
	if provider == nil {
		t.Error("Provider should not be nil")
	}
}

func TestPatreonProvider_ValidateConfig(t *testing.T) {
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
			provider := &patreonProvider{
				OAuth2Config: &goauth.OAuth2Config{
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

func TestPatreonProvider_FetchUser(t *testing.T) {
	mockUser := struct {
		Data struct {
			Id         string `json:"id"`
			Attributes struct {
				FullName string `json:"full_name"`
				Email    string `json:"email"`
				ImageUrl string `json:"image_url"`
			} `json:"attributes"`
		} `json:"data"`
	}{
		Data: struct {
			Id         string `json:"id"`
			Attributes struct {
				FullName string `json:"full_name"`
				Email    string `json:"email"`
				ImageUrl string `json:"image_url"`
			} `json:"attributes"`
		}{
			Id: "123",
			Attributes: struct {
				FullName string `json:"full_name"`
				Email    string `json:"email"`
				ImageUrl string `json:"image_url"`
			}{
				FullName: "Test User",
				Email:    "test@example.com",
				ImageUrl: "https://example.com/avatar.jpg",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/oauth2/v2/identity" {
			t.Errorf("Expected path '/api/oauth2/v2/identity', got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Expected Authorization header 'Bearer test-token', got %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(mockUser)
	}))
	defer server.Close()

	provider := &patreonProvider{
		OAuth2Config: &goauth.OAuth2Config{
			UserApiUrl: server.URL + "/api/oauth2/v2/identity",
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

	if user.Id != mockUser.Data.Id {
		t.Errorf("Expected user ID %s, got %s", mockUser.Data.Id, user.Id)
	}
	if user.Name != mockUser.Data.Attributes.FullName {
		t.Errorf("Expected name %s, got %s", mockUser.Data.Attributes.FullName, user.Name)
	}
	if user.Email != mockUser.Data.Attributes.Email {
		t.Errorf("Expected email %s, got %s", mockUser.Data.Attributes.Email, user.Email)
	}
	if user.AvatarUrl != mockUser.Data.Attributes.ImageUrl {
		t.Errorf("Expected avatar URL %s, got %s", mockUser.Data.Attributes.ImageUrl, user.AvatarUrl)
	}
}

func TestPatreonProvider_RefreshToken(t *testing.T) {
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
		if r.FormValue("client_id") != "test-client-id" {
			t.Errorf("Expected client_id 'test-client-id', got %s", r.FormValue("client_id"))
		}
		if r.FormValue("client_secret") != "test-client-secret" {
			t.Errorf("Expected client_secret 'test-client-secret', got %s", r.FormValue("client_secret"))
		}
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	provider := &patreonProvider{
		OAuth2Config: &goauth.OAuth2Config{},
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
