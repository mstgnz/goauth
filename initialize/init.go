package initialize

import (
	"fmt"

	provider "github.com/mstgnz/goauth"
	"github.com/mstgnz/goauth/apple"
	"github.com/mstgnz/goauth/discord"
	"github.com/mstgnz/goauth/facebook"
	"github.com/mstgnz/goauth/gitea"
	"github.com/mstgnz/goauth/gitee"
	"github.com/mstgnz/goauth/github"
	"github.com/mstgnz/goauth/gitlab"
	"github.com/mstgnz/goauth/google"
	"github.com/mstgnz/goauth/instagram"
	"github.com/mstgnz/goauth/kakao"
	"github.com/mstgnz/goauth/livechat"
	"github.com/mstgnz/goauth/mailcow"
	"github.com/mstgnz/goauth/microsoft"
	"github.com/mstgnz/goauth/oidc"
	"github.com/mstgnz/goauth/patreon"
	"github.com/mstgnz/goauth/spotify"
	"github.com/mstgnz/goauth/strava"
	"github.com/mstgnz/goauth/twitch"
	"github.com/mstgnz/goauth/vk"
	"github.com/mstgnz/goauth/x"
	"github.com/mstgnz/goauth/yandex"
)

var (
	// providers holds all registered OAuth2 providers.
	providers = map[string]func() provider.Provider{}
)

// init registers all available OAuth2 providers.
func init() {
	providers = map[string]func() provider.Provider{
		"apple":     apple.NewAppleProvider,
		"discord":   discord.NewDiscordProvider,
		"facebook":  facebook.NewFacebookProvider,
		"github":    github.NewGithubProvider,
		"gitlab":    gitlab.NewGitlabProvider,
		"gitea":     gitea.NewGiteaProvider,
		"gitee":     gitee.NewGiteeProvider,
		"google":    google.NewGoogleProvider,
		"instagram": instagram.NewInstagramProvider,
		"kakao":     kakao.NewKakaoProvider,
		"livechat":  livechat.NewLiveChatProvider,
		"mailcow":   mailcow.NewMailcowProvider,
		"microsoft": microsoft.NewMicrosoftProvider,
		"oidc":      oidc.NewOidcProvider,
		"patreon":   patreon.NewPatreonProvider,
		"spotify":   spotify.NewSpotifyProvider,
		"strava":    strava.NewStravaProvider,
		"twitch":    twitch.NewTwitchProvider,
		"x":         x.NewXProvider,
		"vk":        vk.NewVkProvider,
		"yandex":    yandex.NewYandexProvider,
	}
}

// NewProviderByName creates a new OAuth2 provider instance by its name.
func NewProviderByName(name string) (provider.Provider, error) {
	if provider, ok := providers[name]; ok {
		return provider(), nil
	}
	return nil, fmt.Errorf("provider %s not found", name)
}
