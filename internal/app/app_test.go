package app

import "testing"

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
