// Package ui owns every byte the CLI shows a human or a program. Commands
// describe what they produced - a collection, a record, a document, or the
// result of a mutation - and this package decides how it looks in text and how
// it is shaped in JSON or YAML. Nothing outside this package writes to the
// process streams.
//
// The package knows nothing about Proton: no IDs are resolved here, no caches
// are written, no API types are imported. That keeps it testable against golden
// files with no fixtures.
package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/roman-16/proton-cli/internal/errs"
	"golang.org/x/term"
)

// Format is how the answer is serialised.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// ParseFormat maps the --output value to a Format.
func ParseFormat(s string) (Format, error) {
	switch s {
	case "", "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "yaml", "yml":
		return FormatYAML, nil
	}
	return "", fmt.Errorf("--output accepts: text, json, yaml")
}

// Machine reports whether the format is for a program rather than a person.
func (f Format) Machine() bool { return f != FormatText }

// LogLevels is the domain of --log-level, in increasing severity.
var LogLevels = []string{"debug", "info", "warn", "error"}

// ParseLogLevel resolves how noisy the logger should be: the flag if given, else
// PROTON_LOG_LEVEL, else warnings and worse.
//
// An unrecognised value is refused rather than quietly becoming the default. A
// mistyped --log-level used to produce silence, which looks exactly like the
// logging working and there being nothing to say.
//
// The variable is not profile-scoped: how much this machine should say is a
// property of the machine, not of the account being used on it.
func ParseLogLevel(flag string) (slog.Level, error) {
	v := strings.ToLower(strings.TrimSpace(flag))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(os.Getenv("PROTON_LOG_LEVEL")))
	}
	switch v {
	case "":
		return slog.LevelWarn, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelWarn, fmt.Errorf("--log-level accepts: %s", strings.Join(LogLevels, ", "))
}

// UI is the renderer for one invocation.
//
// Out carries the answer; Err carries everything about producing it. That split
// is absolute: a redirect of stdout must yield exactly the data and nothing
// else.
type UI struct {
	Format Format
	Out    io.Writer
	Err    io.Writer
	In     io.Reader
	Log    *slog.Logger

	// Quiet suppresses confirmations, notes and progress on Err.
	Quiet bool
	// NoInput forbids prompting, so a missing credential is an error instead of
	// a question.
	NoInput bool
	// FullIDs keeps IDs unshortened even on a terminal.
	FullIDs bool
	// Width overrides the assumed terminal width for table layout. Zero measures
	// the output stream, falling back to a sane default when it is not a
	// terminal.
	Width int

	// theme styles Out, errTheme styles Err. Both are disabled unless that
	// stream is a terminal and the format is text, so piped bytes never carry
	// escape sequences.
	theme    Theme
	errTheme Theme
}

// Options configures a UI. Out, Err and In default to the process streams.
type Options struct {
	Format   Format
	Out      io.Writer
	Err      io.Writer
	In       io.Reader
	LogLevel slog.Level
	Quiet    bool
	NoColor  bool
	NoInput  bool
	FullIDs  bool
	Width    int
}

func New(opts Options) *UI {
	out, errw, in := opts.Out, opts.Err, opts.In
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	if in == nil {
		in = os.Stdin
	}
	var theme, errTheme Theme
	if opts.Format == FormatText && !opts.NoColor {
		theme, errTheme = ThemeFor(out), ThemeFor(errw)
	}
	return &UI{
		Format:   opts.Format,
		Out:      out,
		Err:      errw,
		In:       in,
		Log:      slog.New(slog.NewTextHandler(errw, &slog.HandlerOptions{Level: opts.LogLevel})),
		Quiet:    opts.Quiet,
		NoInput:  opts.NoInput || NoInput(),
		FullIDs:  opts.FullIDs,
		Width:    opts.Width,
		theme:    theme,
		errTheme: errTheme,
	}
}

// Theme returns the palette for Out.
func (u *UI) Theme() Theme { return u.theme }

// ErrTheme returns the palette for Err.
func (u *UI) ErrTheme() Theme { return u.errTheme }

// IsTTY reports whether the answer is going to a terminal, which is what
// decides ID shortening: a pipe wants full IDs even when the user's stderr is
// still a terminal.
//
// PROTON_CLI_FORCE_TTY=1 overrides the check so tests can exercise interactive
// rendering without a pty. It deliberately does not enable colour.
func (u *UI) IsTTY() bool {
	if os.Getenv("PROTON_CLI_FORCE_TTY") == "1" {
		return true
	}
	f, ok := u.Out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// ShortIDs reports whether IDs should be shortened for display.
func (u *UI) ShortIDs() bool { return u.IsTTY() && !u.FullIDs }

// preview returns a UI whose answer stream is this one's commentary stream.
//
// A dry run explains rather than answers: it produces no data, so everything it
// draws - the table of what would be affected included - belongs on stderr,
// where it survives a redirect of stdout. The clone is quiet because the count
// has already been stated in the line above the table.
func (u *UI) preview() *UI {
	p := *u
	p.Out = u.Err
	p.theme = u.errTheme
	p.Quiet = true
	return &p
}

// silent returns a clone that writes no commentary, for a renderer nested
// inside a larger response whose surroundings already say what it is.
func (u *UI) silent() *UI {
	s := *u
	s.Quiet = true
	return &s
}

// Note writes an incidental line to Err. Suppressed by --quiet.
func (u *UI) Note(msg string) {
	if u.Quiet || msg == "" {
		return
	}
	_, _ = fmt.Fprintln(u.Err, msg)
}

// Notef is Note with formatting.
func (u *UI) Notef(format string, a ...any) { u.Note(fmt.Sprintf(format, a...)) }

// Hint writes a dimmed incidental line to Err.
func (u *UI) Hint(msg string) {
	if u.Quiet || msg == "" {
		return
	}
	_, _ = fmt.Fprintln(u.Err, u.errTheme.Hint(msg))
}

// encode writes v to Out in the machine format. It is the single marshalling
// path, so JSON and YAML can never disagree about field names: goccy/go-yaml
// falls back to `json:"..."` tags when no `yaml:"..."` tag is present.
func (u *UI) encode(v any) error {
	if u.Format == FormatYAML {
		b, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		_, err = u.Out.Write(b)
		return err
	}
	enc := json.NewEncoder(u.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Raw writes pre-formatted JSON bytes through, re-encoding for YAML. It exists
// for `proton-cli api`, the one command whose contract is Proton's own shape.
//
// Numbers are decoded via json.Number so YAML keeps integer fields integral
// rather than rendering 1000 as 1000.0.
// Invalid JSON goes to stderr and fails the command.
func Raw(u *UI, raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		_, _ = u.Err.Write(raw)
		if raw[len(raw)-1] != '\n' {
			_, _ = fmt.Fprintln(u.Err)
		}
		return errs.Problemf("The API returned a body that is not JSON.").Exit(5)
	}
	return u.encode(plainNumbers(v))
}

// plainNumbers converts json.Number to int64 where it fits, else float64, so
// both encoders emit numbers rather than quoted strings.
func plainNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	case map[string]any:
		for k, vv := range x {
			x[k] = plainNumbers(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = plainNumbers(vv)
		}
		return x
	}
	return v
}
