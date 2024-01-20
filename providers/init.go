package goauth

import (
	"errors"

	"github.com/mstgnz/goauth/defines"
)

// providerMap is a map that associates Provider names with their corresponding constructor functions.
var providerMap = make(map[string]interface{})

// NewProviderByName returns a new preconfigured provider instance by its name identifier.
func NewProviderByName(name string) (goauth.Provider, error) {
	constructorFunc, ok := providerMap[name]
	if ok {
		return constructorFunc.(func() goauth.Provider)(), nil
	}
	return constructorFunc.(func() goauth.Provider)(), errors.New("Missing provider " + name)
}

// registerProvider registers a Provider constructor function with a given name.
func registerProvider[T goauth.Provider](name string, constructor func() T) {
	providerMap[name] = constructor
}

func init() {
	registerProvider("appleProvider", newAppleProvider)
	registerProvider("discordProvider", newDiscordProvider)
	registerProvider("facebookProvider", newFacebookProvider)
	registerProvider("giteaProvider", newGiteaProvider)
	registerProvider("giteeProvider", newGiteeProvider)
	registerProvider("github", newGithubProvider)
	registerProvider("gitlabProvider", newGitlabProvider)
	registerProvider("googleProvider", newGoogleProvider)
	registerProvider("instagramProvider", newInstagramProvider)
	registerProvider("kakaoProvider", newKakaoProvider)
	registerProvider("livechatProvider", newLivechatProvider)
	registerProvider("mailcowProvider", newMailcowProvider)
	registerProvider("microsoftProvider", newMicrosoftProvider)
	registerProvider("oidcProvider", newOidcProvider)
	registerProvider("oidc2", newOidcProvider)
	registerProvider("oidc3", newOidcProvider)
	registerProvider("patreonProvider", newPatreonProvider)
	registerProvider("spotifyProvider", newSpotifyProvider)
	registerProvider("stravaProvider", newStravaProvider)
	registerProvider("twitchProvider", newTwitchProvider)
	registerProvider("twitterProvider", newTwitterProvider)
	registerProvider("vkProvider", newVKProvider)
	registerProvider("yandexProvider", newYandexProvider)
}
