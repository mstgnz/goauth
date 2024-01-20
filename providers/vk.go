package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mstgnz/goauth/defines"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"
)

// vkProvider allows authentication via vkProvider OAuth2.
type vkProvider struct {
	*goauth.OAuth2Config
}

// newVKProvider creates new vkProvider provider instance with some defaults.
// Docs: https://dev.vk.com/api/oauth-parameters
func newVKProvider() goauth.Provider {
	return &vkProvider{&goauth.OAuth2Config{
		Ctx:         context.Background(),
		DisplayName: "vkProvider",
		AuthUrl:     vk.Endpoint.AuthURL,
		TokenUrl:    vk.Endpoint.TokenURL,
		UserApiUrl:  "https://api.vk.com/method/users.get?fields=photo_max,screen_name&v=5.131",
		Scopes:      []string{"email"},
		Pkce:        false, // vkProvider currently doesn't support GetPKCE and throws an error if GetPKCE params are send
	}}
}

// FetchUser returns a Credential instance based on vkProvider's user api.
// API reference: https://dev.vk.com/method/users.get
func (v *vkProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := v.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Response []struct {
			Id        int    `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Username  string `json:"screen_name"`
			AvatarUrl string `json:"photo_max"`
		} `json:"response"`
	}{}

	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	if len(extracted.Response) == 0 {
		return nil, errors.New("missing response entry")
	}

	user := &goauth.Credential{
		Id:           strconv.Itoa(extracted.Response[0].Id),
		Name:         strings.TrimSpace(extracted.Response[0].FirstName + " " + extracted.Response[0].LastName),
		Username:     extracted.Response[0].Username,
		AvatarUrl:    extracted.Response[0].AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if email := token.Extra("email"); email != nil {
		user.Email = fmt.Sprint(email)
	}

	return user, nil
}
