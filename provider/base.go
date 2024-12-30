package provider

import (
	"errors"

	"golang.org/x/oauth2"
)

// provider.BaseProvider implements common functionality for all providers
type BaseProvider struct{}

// ValidateConfig implements the common validation logic for all providers
func (b *BaseProvider) ValidateConfig(clientId, clientSecret, redirectUrl string) error {
	if clientId == "" {
		return errors.New("client ID is required")
	}
	if clientSecret == "" {
		return errors.New("client secret is required")
	}
	if redirectUrl == "" {
		return errors.New("redirect URL is required")
	}
	return nil
}

// RefreshTokenNotSupported returns a standard error for providers that don't support token refresh
func (b *BaseProvider) RefreshTokenNotSupported() (*oauth2.Token, error) {
	return nil, errors.New("refresh token is not supported by this provider")
}
