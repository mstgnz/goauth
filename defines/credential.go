package goauth

// Credential defines a standardized OAuth2 user data structure.
// It represents the information retrieved from the OAuth2 provider's user API.
type Credential struct {
	Id           string         `json:"id"`
	Name         string         `json:"name"`
	Username     string         `json:"username"`
	Email        string         `json:"email"`
	AvatarUrl    string         `json:"avatarUrl"`
	AccessToken  string         `json:"accessToken"`
	RefreshToken string         `json:"refreshToken"`
	Expiry       string         `json:"expiry"`
	RawUser      map[string]any `json:"rawUser"`
}
