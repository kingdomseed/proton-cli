package session

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// A session without a sealed key password is one that still needs the account
// password to decrypt anything; Unlocked is how the account commands report the
// difference.
func TestUnlockedTracksTheSealedKeyPassword(t *testing.T) {
	if (&Session{UID: "u"}).Unlocked() {
		t.Error("a session with no blob is not unlocked")
	}
	if !(&Session{UID: "u", EncKeyBlob: "blob"}).Unlocked() {
		t.Error("a session with a blob is unlocked")
	}
	var none *Session
	if none.Unlocked() {
		t.Error("a missing session is not unlocked")
	}
}

func TestPathInNamedProfile(t *testing.T) {
	d := t.TempDir()
	got, err := pathIn(d, "work")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d, "sessions", "work.json")
	if got != want {
		t.Errorf("pathIn(work) = %q, want %q", got, want)
	}
}

func TestPathInEmptyTreatedAsDefault(t *testing.T) {
	d := t.TempDir()
	got, err := pathIn(d, "")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d, "sessions", "default.json")
	if got != want {
		t.Errorf("pathIn(\"\") = %q, want %q", got, want)
	}
}

func TestPathInDefault(t *testing.T) {
	d := t.TempDir()
	got, err := pathIn(d, "default")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(d, "sessions", "default.json")
	if got != want {
		t.Errorf("pathIn(default) = %q, want %q", got, want)
	}
}

func TestNormalizeProfileAcceptsSafeNames(t *testing.T) {
	for _, name := range []string{"default", "work", "Work-2", "mail.backup", "account_3"} {
		if got, err := NormalizeProfile(name); err != nil || got != name {
			t.Errorf("NormalizeProfile(%q) = %q, %v", name, got, err)
		}
	}
	if got, err := NormalizeProfile(""); err != nil || got != "default" {
		t.Errorf("NormalizeProfile(empty) = %q, %v", got, err)
	}
}

func TestNormalizeProfileRejectsPathsAndUnsupportedNames(t *testing.T) {
	for _, name := range []string{"../work", "/tmp/work", `.\\work`, "two words", "müller", "-work"} {
		if _, err := NormalizeProfile(name); err == nil {
			t.Errorf("NormalizeProfile(%q) accepted an unsafe name", name)
		}
	}
	if _, err := NormalizeProfile(strings.Repeat("a", maxProfileNameBytes+1)); err == nil {
		t.Error("NormalizeProfile accepted an overlong name")
	}
}

func TestPathInRejectsTraversal(t *testing.T) {
	if _, err := pathIn(t.TempDir(), "../../outside"); err == nil {
		t.Fatal("pathIn accepted directory traversal")
	}
}

func TestSessionMarshalUsesEncKeyBlob(t *testing.T) {
	b, err := json.Marshal(Session{UID: "u", AccessToken: "a", RefreshToken: "r", EncKeyBlob: "blob"})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, `"enc_key_blob":"blob"`) {
		t.Errorf("expected enc_key_blob in JSON, got: %s", out)
	}
	if strings.Contains(out, "salted_key_pass") {
		t.Errorf("salted_key_pass field should not exist, got: %s", out)
	}
}
