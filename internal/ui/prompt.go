package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/roman-16/proton-cli/internal/errs"
	"golang.org/x/term"
)

// This file is the only place in the CLI that reads from standard input for a
// value the user is being asked for. Keeping it to one file is what makes the
// scripting contract checkable: a command can only ever block on input if it
// went through here.

// ErrNoInput reports that a value was needed but could not be asked for.
var ErrNoInput = errs.Problemf("input is required but the terminal is not interactive")

// NoInput reports whether the environment forbids prompting, honouring
// PROTON_NO_INPUT.
//
// Presence is what counts, whatever the value - the same rule NO_COLOR follows.
// Two variables that both switch a behaviour off should not need two different
// mental models, and `PROTON_NO_INPUT=` in a CI environment file reads as
// intent either way.
//
// It is deliberately not profile-scoped, unlike most PROTON_ variables: whether
// a terminal can be asked a question is a property of the machine, not of the
// account being used on it.
func NoInput() bool {
	_, set := os.LookupEnv("PROTON_NO_INPUT")
	return set
}

// CanPrompt reports whether asking a question is possible: input has to be a
// terminal, and prompting must not have been forbidden.
//
// Everything else in the CLI stays non-interactive, so a cron job fails with a
// message instead of hanging on a question nobody will answer.
//
// An In that is not a file is a test's buffer, which can always be read and
// never blocks; that is what lets the confirmations be pinned by golden files
// rather than trusted.
func (u *UI) CanPrompt() bool {
	if u.NoInput {
		return false
	}
	if f, ok := u.In.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return u.In != nil
}

// Confirm asks a yes/no question and reports whether the answer was yes.
//
// The default is no. A bare newline, an unreadable stdin or anything that is not
// a plain yes all mean no, so the dangerous path is the one that has to be typed
// out. Like every other prompt, the question goes to Err: it is not an answer.
func (u *UI) Confirm(question string) (bool, error) {
	if !u.CanPrompt() {
		return false, ErrNoInput
	}
	_, _ = fmt.Fprintf(u.Err, "%s %s ", question, u.errTheme.Hint("[y/N]"))
	line, err := bufio.NewReader(u.In).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// Prompter shares one reader so answers typed ahead are not lost.
type Prompter struct {
	u  *UI
	in *bufio.Reader
}

// Ask returns a Prompter reading from this UI's input.
func (u *UI) Ask() *Prompter {
	return &Prompter{u: u, in: bufio.NewReader(u.In)}
}

// Line asks for a visible value.
func (p *Prompter) Line(label string) (string, error) {
	if !p.u.CanPrompt() {
		return "", ErrNoInput
	}
	p.write(label)
	s, err := p.in.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// Secret asks for a value without echoing it. The bytes are never written
// anywhere but the caller's variable.
//
// Turning the echo off needs a terminal rather than a stream, so this reads the
// descriptor directly when there is one and falls back to an ordinary line
// otherwise - the fallback only being reachable from a test, since CanPrompt
// has already refused a non-terminal file.
func (p *Prompter) Secret(label string) (string, error) {
	if !p.u.CanPrompt() {
		return "", ErrNoInput
	}
	p.write(label)
	f, isFile := p.u.In.(*os.File)
	if !isFile {
		s, err := p.in.ReadString('\n')
		if err != nil && s == "" {
			return "", err
		}
		return strings.TrimSpace(s), nil
	}
	b, err := term.ReadPassword(int(f.Fd()))
	// ReadPassword swallows the newline the user typed; put it back so the next
	// line of output does not land on the prompt.
	_, _ = fmt.Fprintln(p.u.Err)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// write emits the prompt on stderr, never stdout: a question is not an answer,
// so redirecting the answer must not capture it.
func (p *Prompter) write(label string) {
	_, _ = fmt.Fprintf(p.u.Err, "%s ", p.u.errTheme.Hint(label+":"))
}
