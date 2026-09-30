package app

import (
	"github.com/roman-16/proton-cli/internal/errs"
	"github.com/roman-16/proton-cli/internal/ui"
)

// Credentials resolves the three values that identify and unlock an account.
//
// It is the only thing in the CLI that may ask a person for one. Every other
// command stays non-interactive and fails with a message, so a scheduled job can
// never hang waiting on a question nobody will answer.
//
// Resolution order, most specific first:
//
//  1. the flag (--user, --password, --totp)
//  2. the profile-scoped variable (PROTON_WORK_PASSWORD)
//  3. the plain variable (PROTON_PASSWORD)
//  4. a prompt, when input is a terminal and --no-input was not given
//
// Each value is asked for at most once per invocation: a command that needs the
// password twice does not ask twice.
type Credentials struct {
	profile string
	ui      *ui.UI

	flagUser     string
	flagPassword string
	flagTOTP     string

	user, password, totp string
	haveUser             bool
	havePassword         bool
	haveTOTP             bool
	prompt               *ui.Prompter
}

// The labels used by the login prompts.
const (
	labelEmail    = "Email"
	labelPassword = "Password"
	labelTOTP     = "Two-factor code"
)

func newCredentials(profile string, u *ui.UI, flagUser, flagPassword, flagTOTP string) *Credentials {
	return &Credentials{
		profile: profile, ui: u,
		flagUser: flagUser, flagPassword: flagPassword, flagTOTP: flagTOTP,
	}
}

// HaveUser reports whether an account email is available without asking for it.
// Used to decide whether a value is worth reporting, never to gate a prompt.
func (c *Credentials) HaveUser() bool {
	return c.haveUser || c.flagUser != "" || envForProfile(c.profile, "USER") != ""
}

// User returns the account email.
func (c *Credentials) User() (string, error) {
	if c.haveUser {
		return c.user, nil
	}
	v, err := c.resolve(c.flagUser, "USER", labelEmail, false,
		errs.Problemf("An account email is required.").
			Hint("set PROTON_USER, pass --user, or run this in a terminal."))
	if err != nil {
		return "", err
	}
	c.user, c.haveUser = v, true
	return v, nil
}

// Password returns the account password. reason completes the sentence "Your
// password is required to <reason>", so it reads as a clause: "sign in",
// "unlock your keys", "delete a calendar".
func (c *Credentials) Password(reason string) (string, error) {
	if c.havePassword {
		return c.password, nil
	}
	// Say why before asking. A password prompt appearing mid-command with no
	// explanation is indistinguishable from something going wrong.
	if c.flagPassword == "" && envForProfile(c.profile, "PASSWORD") == "" && c.ui.CanPrompt() {
		c.ui.Notef("Your password is required to %s.", reason)
	}
	v, err := c.resolve(c.flagPassword, "PASSWORD", labelPassword, true,
		errs.Problemf("Your password is required to %s.", reason).
			Hint("set PROTON_PASSWORD, pass --password, or run this in a terminal."))
	if err != nil {
		return "", err
	}
	c.password, c.havePassword = v, true
	return v, nil
}

// TOTP returns the current two-factor code.
//
// A TOTP rotates every thirty seconds, which makes an exported variable stale
// almost immediately, so this is the value a prompt helps with most.
func (c *Credentials) TOTP() (string, error) {
	if c.haveTOTP {
		return c.totp, nil
	}
	v, err := c.resolve(c.flagTOTP, "TOTP", labelTOTP, false,
		errs.Problemf("This account has two-factor authentication enabled, so a code is required.").
			Hint("set PROTON_TOTP, pass --totp, or run this in a terminal.").Exit(2))
	if err != nil {
		return "", err
	}
	c.totp, c.haveTOTP = v, true
	return v, nil
}

// TOTPIfSet returns a two-factor code only if one was already supplied by a flag
// or the environment. It never asks, for callers that would rather proceed and
// let the server say whether a code was needed.
func (c *Credentials) TOTPIfSet() string {
	if c.haveTOTP {
		return c.totp
	}
	if c.flagTOTP != "" {
		return c.flagTOTP
	}
	return envForProfile(c.profile, "TOTP")
}

// resolve walks the sources in order, asking only as a last resort.
func (c *Credentials) resolve(flag, env, label string, secret bool, missing error) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if v := envForProfile(c.profile, env); v != "" {
		return v, nil
	}
	if !c.ui.CanPrompt() {
		return "", missing
	}
	if c.prompt == nil {
		c.prompt = c.ui.Ask()
	}
	ask := c.prompt
	var (
		v   string
		err error
	)
	if secret {
		v, err = ask.Secret(label)
	} else {
		v, err = ask.Line(label)
	}
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", missing
	}
	return v, nil
}
