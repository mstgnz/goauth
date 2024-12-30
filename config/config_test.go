package config

import (
	"context"
	"testing"

	"golang.org/x/oauth2"
)

func TestContext(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetScopes()
	if before != nil {
		t.Errorf("Expected nil context, got %v", before)
	}

	b.SetContext(context.Background())

	after := b.GetScopes()
	if after != nil {
		t.Error("Expected non-nil context")
	}
}

func TestDisplayName(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetDisplayName()
	if before != "" {
		t.Fatalf("Expected DisplayName to be empty, got %v", before)
	}

	b.SetDisplayName("test")

	after := b.GetDisplayName()
	if after != "test" {
		t.Fatalf("Expected DisplayName to be 'test', got %v", after)
	}
}

func TestClientId(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetClientId()
	if before != "" {
		t.Fatalf("Expected ClientId to be empty, got %v", before)
	}

	b.SetClientId("test")

	after := b.GetClientId()
	if after != "test" {
		t.Fatalf("Expected ClientId to be 'test', got %v", after)
	}
}

func TestClientSecret(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetClientSecret()
	if before != "" {
		t.Fatalf("Expected GetClientSecret to be empty, got %v", before)
	}

	b.SetClientSecret("test")

	after := b.GetClientSecret()
	if after != "test" {
		t.Fatalf("Expected GetClientSecret to be 'test', got %v", after)
	}
}

func TestRedirectUrl(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetRedirectUrl()
	if before != "" {
		t.Fatalf("Expected GetRedirectUrl to be empty, got %v", before)
	}

	b.SetRedirectUrl("test")

	after := b.GetRedirectUrl()
	if after != "test" {
		t.Fatalf("Expected GetRedirectUrl to be 'test', got %v", after)
	}
}

func TestAuthUrl(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetAuthUrl()
	if before != "" {
		t.Fatalf("Expected AuthUrl to be empty, got %v", before)
	}

	b.SetAuthUrl("test")

	after := b.GetAuthUrl()
	if after != "test" {
		t.Fatalf("Expected AuthUrl to be 'test', got %v", after)
	}
}

func TestTokenUrl(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetTokenUrl()
	if before != "" {
		t.Fatalf("Expected TokenUrl to be empty, got %v", before)
	}

	b.SetTokenUrl("test")

	after := b.GetTokenUrl()
	if after != "test" {
		t.Fatalf("Expected TokenUrl to be 'test', got %v", after)
	}
}

func TestUserApiUrl(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetUserApiUrl()
	if before != "" {
		t.Fatalf("Expected UserApiUrl to be empty, got %v", before)
	}

	b.SetUserApiUrl("test")

	after := b.GetUserApiUrl()
	if after != "test" {
		t.Fatalf("Expected UserApiUrl to be 'test', got %v", after)
	}
}

func TestScopes(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetScopes()
	if len(before) != 0 {
		t.Fatalf("Expected 0 Scopes, got %v", before)
	}

	b.SetScopes([]string{"test1", "test2"})

	after := b.GetScopes()
	if len(after) != 2 {
		t.Fatalf("Expected 2 Scopes, got %v", after)
	}
}

func TestPKCE(t *testing.T) {
	b := OAuth2Config{}

	before := b.GetPKCE()
	if before != false {
		t.Fatalf("Expected Pkce to be %v, got %v", false, before)
	}

	b.SetPKCE(true)

	after := b.GetPKCE()
	if after != true {
		t.Fatalf("Expected Pkce to be %v, got %v", true, after)
	}
}

func TestClient(t *testing.T) {
	b := OAuth2Config{}

	result := b.Client(&oauth2.Token{})
	if result == nil {
		t.Error("Expected *http.Client instance, got nil")
	}
}

func TestBuildAuthUrl(t *testing.T) {
	b := OAuth2Config{
		AuthUrl:      "authUrl_test",
		TokenUrl:     "tokenUrl_test",
		RedirectUrl:  "redirectUrl_test",
		ClientId:     "clientId_test",
		ClientSecret: "clientSecret_test",
		Scopes:       []string{"test_scope"},
	}

	expected := "authUrl_test?access_type=offline&client_id=clientId_test&prompt=consent&redirect_uri=redirectUrl_test&response_type=code&scope=test_scope&state=state_test"
	result := b.BuildAuthUrl("state_test", oauth2.AccessTypeOffline, oauth2.ApprovalForce)

	if result != expected {
		t.Errorf("Expected auth url %q, got %q", expected, result)
	}
}

func TestOauth2Config(t *testing.T) {
	b := OAuth2Config{
		AuthUrl:      "authUrl_test",
		TokenUrl:     "tokenUrl_test",
		RedirectUrl:  "redirectUrl_test",
		ClientId:     "clientId_test",
		ClientSecret: "clientSecret_test",
		Scopes:       []string{"test"},
	}

	result := b.oauth2Config()

	if result.RedirectURL != b.GetRedirectUrl() {
		t.Errorf("Expected RedirectUrl %s, got %s", b.GetRedirectUrl(), result.RedirectURL)
	}

	if result.ClientID != b.GetClientId() {
		t.Errorf("Expected ClientId %s, got %s", b.GetClientId(), result.ClientID)
	}

	if result.ClientSecret != b.GetClientSecret() {
		t.Errorf("Expected GetClientSecret %s, got %s", b.GetClientSecret(), result.ClientSecret)
	}

	if result.Endpoint.AuthURL != b.GetAuthUrl() {
		t.Errorf("Expected AuthUrl %s, got %s", b.GetAuthUrl(), result.Endpoint.AuthURL)
	}

	if result.Endpoint.TokenURL != b.GetTokenUrl() {
		t.Errorf("Expected AuthUrl %s, got %s", b.GetTokenUrl(), result.Endpoint.TokenURL)
	}

	if len(result.Scopes) != len(b.GetScopes()) || result.Scopes[0] != b.GetScopes()[0] {
		t.Errorf("Expected Scopes %s, got %s", b.GetScopes(), result.Scopes)
	}
}
