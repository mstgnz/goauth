package goauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mstgnz/goauth/defines"
	"github.com/spf13/cast"
	"golang.org/x/oauth2"
)

// appleProvider allows authentication via Apple OAuth2.
// [OIDC differences]: https://bitbucket.org/openid/connect/src/master/How-Sign-in-with-Apple-differs-from-OpenID-Connect.md
type appleProvider struct {
	*goauth.OAuth2Config

	jwkUrl string
}

// newAppleProvider creates a new Apple provider instance with some defaults.
func newAppleProvider() goauth.Provider {
	return &appleProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "appleProvider",
			AuthUrl:     "https://appleid.apple.com/auth/authorize",
			TokenUrl:    "https://appleid.apple.com/auth/token",
			Scopes:      nil, // Custom scopes are currently not supported since they require a POST redirect
			Pkce:        true,
		},
		jwkUrl: "https://appleid.apple.com/auth/keys",
	}
}

// FetchUser returns a Credential instance based on the provided token.
// API reference: https://developer.apple.com/documentation/sign_in_with_apple/tokenresponse.
func (a *appleProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := a.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Id            string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"` // could be string or bool
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           extracted.Id,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if cast.ToBool(extracted.EmailVerified) {
		user.Email = extracted.Email
	}

	return user, nil
}

// FetchRawData implements Provider.FetchRawData interface.
// Apple doesn't have a UserInfo endpoint, and claims about users
// are instead included in the "id_token" (https://openid.net/specs/openid-connect-core-1_0.html#id_tokenExample)
func (a *appleProvider) FetchRawData(token *oauth2.Token) ([]byte, error) {
	idToken, _ := token.Extra("id_token").(string)

	claims, err := a.parseAndVerifyIdToken(idToken)
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

func (a *appleProvider) parseAndVerifyIdToken(idToken string) (jwt.MapClaims, error) {
	if idToken == "" {
		return nil, errors.New("empty id_token")
	}

	// extract the token header params and claims
	claims := jwt.MapClaims{}
	t, _, err := jwt.NewParser().ParseUnverified(idToken, claims)
	if err != nil {
		return nil, err
	}

	// fetch the public key set
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("missing kid header value")
	}

	key, err := a.fetchJWK(kid)
	if err != nil {
		return nil, err
	}

	// decode the key params per RFC 7518 (https://tools.ietf.org/html/rfc7518#section-6.3)
	// and construct a valid publicKey from them
	exponent, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key.e, "="))
	if err != nil {
		return nil, err
	}

	modulus, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key.n, "="))
	if err != nil {
		return nil, err
	}

	publicKey := &rsa.PublicKey{
		// https://tools.ietf.org/html/rfc7517#appendix-A.1
		E: int(big.NewInt(0).SetBytes(exponent).Uint64()),
		N: big.NewInt(0).SetBytes(modulus),
	}

	// verify the id_token
	parser := jwt.NewParser(jwt.WithValidMethods([]string{key.alg}))

	parsedToken, err := parser.Parse(idToken, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, nil
	}

	return nil, errors.New("the parsed id_token is invalid")
}

type jwk struct {
	kty string
	kid string
	use string
	alg string
	n   string
	e   string
}

func (a *appleProvider) fetchJWK(kid string) (*jwk, error) {
	req, err := http.NewRequestWithContext(a.Ctx, "GET", a.jwkUrl, nil)
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)

	rawBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	// http.Client.Get doesn't treat non 2xx responses as error
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf(
			"failed to verify the provided id_token (%d):\n%s",
			res.StatusCode,
			string(rawBody),
		)
	}

	jKeys := struct {
		Keys []*jwk
	}{}
	if err = json.Unmarshal(rawBody, &jKeys); err != nil {
		return nil, err
	}

	for _, key := range jKeys.Keys {
		if key.kid == kid {
			return key, nil
		}
	}

	return nil, fmt.Errorf("jwk with kid %q was not found", kid)
}
