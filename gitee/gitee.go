package gitee

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/mstgnz/goauth"

	"golang.org/x/oauth2"
)

// validator
var validate *validator.Validate

func init() {
	validate = validator.New()
}

// giteeProvider allows authentication via Gitee OAuth2.
type giteeProvider struct {
	*goauth.OAuth2Config
	goauth.BaseProvider
	EmailApiUrl string
}

// NewGiteeProvider creates new Gitee provider instance with some defaults.
func NewGiteeProvider() goauth.Provider {
	return &giteeProvider{
		OAuth2Config: &goauth.OAuth2Config{
			Ctx:         context.Background(),
			DisplayName: "Gitee",
			AuthUrl:     "https://gitee.com/oauth/authorize",
			TokenUrl:    "https://gitee.com/oauth/token",
			UserApiUrl:  "https://gitee.com/api/v5/user",
			Scopes:      []string{"user_info"},
			Pkce:        true,
		},
		BaseProvider: goauth.BaseProvider{},
		EmailApiUrl:  "https://gitee.com/api/v5/emails",
	}
}

// ValidateConfig validates the provider configuration.
func (p *giteeProvider) ValidateConfig() error {
	return p.BaseProvider.ValidateConfig(p.GetClientId(), p.GetClientSecret(), p.GetRedirectUrl())
}

// RefreshToken refreshes the OAuth2 token using the refresh token.
func (p *giteeProvider) RefreshToken(token *oauth2.Token) (*oauth2.Token, error) {
	if token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	config := &oauth2.Config{
		ClientID:     p.GetClientId(),
		ClientSecret: p.GetClientSecret(),
		Endpoint: oauth2.Endpoint{
			TokenURL: p.GetTokenUrl(),
		},
	}

	return config.TokenSource(p.GetContext(), token).Token()
}

// FetchUser returns a Credential instance based the Gitte's user api.
// API reference: https://gitee.com/api/v5/swagger#/getV5User
func (p *giteeProvider) FetchUser(token *oauth2.Token) (*goauth.Credential, error) {
	data, err := p.FetchRawData(token)
	if err != nil {
		return nil, err
	}

	rawUser := map[string]any{}
	if err = json.Unmarshal(data, &rawUser); err != nil {
		return nil, err
	}

	extracted := struct {
		Login     string `json:"login"`
		Id        int    `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarUrl string `json:"avatar_url"`
	}{}
	if err = json.Unmarshal(data, &extracted); err != nil {
		return nil, err
	}

	user := &goauth.Credential{
		Id:           strconv.Itoa(extracted.Id),
		Name:         extracted.Name,
		Username:     extracted.Login,
		AvatarUrl:    extracted.AvatarUrl,
		RawUser:      rawUser,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
	}

	if extracted.Email != "" && validate.Var(extracted.Email, "required,email") == nil {
		// valid public primary email
		user.Email = extracted.Email
	} else {
		// send an additional optional request to retrieve the email
		email, err := p.fetchPrimaryEmail(token)
		if err != nil {
			return nil, err
		}
		user.Email = email
	}

	return user, nil
}

// fetchPrimaryEmail sends an API request to retrieve the verified primary email
func (p *giteeProvider) fetchPrimaryEmail(token *oauth2.Token) (string, error) {
	client := p.Client(token)

	response, err := client.Get(p.EmailApiUrl)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	// ignore common http errors caused by insufficient scope permissions
	if response.StatusCode == 401 || response.StatusCode == 403 || response.StatusCode == 404 {
		return "", nil
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email string
		State string
		Scope []string
	}
	if err = json.Unmarshal(content, &emails); err != nil {
		// ignore unmarshal error in case "Keep my email address private"
		// was set because response.Body will be something like:
		// {"email":"12285415+test@user.noreply.giteegoauth.com"}
		return "", nil
	}

	// extract the first verified primary email
	for _, email := range emails {
		for _, scope := range email.Scope {
			if email.State == "confirmed" && scope == "primary" && validate.Var(email.Email, "required,email") == nil {
				return email.Email, nil
			}
		}
	}

	return "", nil
}
