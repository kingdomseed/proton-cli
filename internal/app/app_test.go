package app

import (
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/ui"
)

func TestCredentialsKeepAnswersTypedAhead(t *testing.T) {
	u := ui.New(ui.Options{In: strings.NewReader("user@example.com\npassword\n123456\n")})
	c := newCredentials("test", u, "", "", "")
	for _, name := range []string{"PROTON_USER", "PROTON_PASSWORD", "PROTON_TOTP", "PROTON_TEST_USER", "PROTON_TEST_PASSWORD", "PROTON_TEST_TOTP"} {
		t.Setenv(name, "")
	}
	if got, err := c.User(); err != nil || got != "user@example.com" {
		t.Fatalf("User = %q, %v", got, err)
	}
	if got, err := c.Password("sign in"); err != nil || got != "password" {
		t.Fatalf("Password = %q, %v", got, err)
	}
	if got, err := c.TOTP(); err != nil || got != "123456" {
		t.Fatalf("TOTP = %q, %v", got, err)
	}
}

func TestDefaultUserAgent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "proton-cli/dev"},
		{"dev", "proton-cli/dev"},
		{"1.2.3", "proton-cli/1.2.3"},
		{"v1.4.2", "proton-cli/v1.4.2"},
	}
	for _, tc := range tests {
		if got := defaultUserAgent(tc.in); got != tc.want {
			t.Errorf("defaultUserAgent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewRejectsUnsafeProfileBeforeSetup(t *testing.T) {
	if _, err := New(Options{Profile: "../../outside"}); err == nil {
		t.Fatal("New accepted an unsafe profile")
	}
}
