package initialize

import (
	"testing"
)

func TestNewProviderByName(t *testing.T) {
	tests := []struct {
		name    string
		want    bool
		wantErr bool
	}{
		{"apple", true, false},
		{"discord", true, false},
		{"facebook", true, false},
		{"github", true, false},
		{"gitlab", true, false},
		{"gitea", true, false},
		{"gitee", true, false},
		{"google", true, false},
		{"instagram", true, false},
		{"kakao", true, false},
		{"livechat", true, false},
		{"mailcow", true, false},
		{"microsoft", true, false},
		{"oidc", true, false},
		{"patreon", true, false},
		{"spotify", true, false},
		{"strava", true, false},
		{"twitch", true, false},
		{"x", true, false},
		{"vk", true, false},
		{"yandex", true, false},
		{"invalid", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProviderByName(tt.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProviderByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got != nil) != tt.want {
				t.Errorf("NewProviderByName() = %v, want %v", got, tt.want)
			}
		})
	}
}
