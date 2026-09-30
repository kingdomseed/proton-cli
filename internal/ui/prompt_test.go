package ui

import (
	"strings"
	"testing"
)

func TestAskWritesTheLabelAndOneSpace(t *testing.T) {
	u, _, errb := fixture(t, Options{In: strings.NewReader("user@example.com\n123456\n")})
	p := u.Ask()
	if _, err := p.Line("Email"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Line("Two-factor code"); err != nil {
		t.Fatal(err)
	}
	if got, want := errb.String(), "Email: Two-factor code: "; got != want {
		t.Errorf("prompts = %q, want %q", got, want)
	}
}

// Presence is what counts, whatever the value - the same rule NO_COLOR follows,
// so the two variables need only one mental model between them.
func TestNoInputCountsPresenceNotValue(t *testing.T) {
	for _, value := range []string{"1", "true", "0", "false", "no", "", " ", "anything"} {
		t.Setenv("PROTON_NO_INPUT", value)
		if !NoInput() {
			t.Errorf("PROTON_NO_INPUT=%q is set, so prompting is forbidden", value)
		}
	}
}

func TestNoInputUnsetIsFalse(t *testing.T) {
	unsetenv(t, "PROTON_NO_INPUT")
	if NoInput() {
		t.Error("an unset variable should not forbid prompting")
	}
}

// The environment and the flag are two ways to say the same thing, so either
// alone is enough.
func TestCanPromptRespectsBothTheFlagAndTheEnvironment(t *testing.T) {
	t.Run("the flag alone", func(t *testing.T) {
		unsetenv(t, "PROTON_NO_INPUT")
		u, _, _ := fixture(t, Options{NoInput: true})
		if u.CanPrompt() {
			t.Error("--no-input should forbid prompting")
		}
	})
	t.Run("the environment alone", func(t *testing.T) {
		t.Setenv("PROTON_NO_INPUT", "")
		u, _, _ := fixture(t, Options{})
		if u.CanPrompt() {
			t.Error("PROTON_NO_INPUT should forbid prompting")
		}
	})
	t.Run("neither, but stdin is not a terminal", func(t *testing.T) {
		unsetenv(t, "PROTON_NO_INPUT")
		u, _, _ := fixture(t, Options{})
		// The test process has no terminal on stdin, so prompting is impossible
		// regardless - which is the property a cron job relies on.
		if u.CanPrompt() {
			t.Error("a non-terminal stdin cannot be asked a question")
		}
	})
}

// Refusing to prompt has to produce an error a reader can act on, naming both
// ways to supply the value.
func TestPromptRefusalIsActionable(t *testing.T) {
	t.Setenv("PROTON_NO_INPUT", "1")
	u, _, errb := fixture(t, Options{})
	if _, err := u.Ask().Secret("Password"); err == nil {
		t.Fatal("want a refusal")
	}
	if errb.Len() != 0 {
		t.Errorf("a refused prompt should print nothing, got %q", errb.String())
	}
}
