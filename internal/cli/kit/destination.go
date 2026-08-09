package kit

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Where downloaded bytes go.
//
// Every command that writes a payload to disk answers the same three questions:
// which path, what if it exists, and can it stream to stdout instead. Answering
// them once means attachments, Drive files, photos and exports behave the same,
// and that `--force` means exactly one thing across the whole CLI.

// Destination is the --output / --output-dir / --force group.
type Destination struct {
	output    string
	outputDir string
	force     bool
}

func (d *Destination) Register(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&d.output, "output", "", "Write to this path, or - for stdout")
	f.StringVar(&d.outputDir, "output-dir", "", "Write into this directory, keeping each item's own name")
	f.BoolVar(&d.force, "force", false, "Overwrite a file that already exists")
}

// Validate rejects combinations that cannot mean anything, before any bytes are
// fetched. single says whether exactly one item is being written.
func (d *Destination) Validate(single bool) error {
	if d.output != "" && d.outputDir != "" {
		return Fail("--output and --output-dir cannot both be given.").
			Hint("--output names one file; --output-dir names a directory to fill.")
	}
	if !single && d.output != "" {
		// Several separate files down one stream arrive as one unusable run of
		// bytes, so stdout is no more of an answer here than a single path is.
		names := "--output names one file"
		if d.output == "-" {
			names = "--output - writes one stream"
		}
		return Fail("%s, but several items were selected.", names).
			Hint("use --output-dir to write them all into a directory.")
	}
	return nil
}

// Stdout reports whether the payload streams to standard output.
func (d *Destination) Stdout() bool { return d.output == "-" }

// Describe names the destination for a confirmation.
func (d *Destination) Describe() string {
	switch {
	case d.output == "-":
		return "stdout"
	case d.output != "":
		return d.output
	case d.outputDir != "":
		return d.outputDir
	}
	return "the current directory"
}

// Write puts data where the flags say, returning the path written, or "" when it
// streamed to stdout.
//
// The collision policy differs by intent, and deliberately so: an explicit
// --output path is refused if it exists, because the user named that exact file
// and silently replacing it would destroy something they did not mention. A name
// the CLI chose itself gets a numbered suffix instead, because there was no
// promise to keep.
func (d *Destination) Write(c *Invocation, name string, data []byte) (string, error) {
	if d.output == "-" {
		_, err := c.UI().Out.Write(data)
		return "", err
	}
	if d.output != "" {
		if !d.force && exists(d.output) {
			return "", Fail("%s already exists.", d.output).Hint("--force to overwrite it.")
		}
		return d.output, os.WriteFile(d.output, data, 0o600)
	}
	if d.outputDir != "" {
		if err := EnsureDir(d.outputDir); err != nil {
			return "", err
		}
	}
	target := filepath.Join(d.outputDir, SafeFilename(name))
	if !d.force {
		free, err := freePath(target)
		if err != nil {
			return "", err
		}
		target = free
	}
	return target, os.WriteFile(target, data, 0o600)
}

// WriteStream writes one payload without keeping the complete payload in
// memory. File output uses a temporary file beside the target, so a failed
// producer does not leave a partial result at the final path.
func (d *Destination) WriteStream(c *Invocation, name string, write func(io.Writer) error) (string, error) {
	if d.output == "-" {
		return "", write(c.UI().Out)
	}
	target, err := d.Reserve(name)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".proton-cli-write-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", err
	}
	if err := write(tmp); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if d.force {
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	if err := os.Rename(tmpName, target); err != nil {
		return "", err
	}
	keep = true
	return target, nil
}

// EnsureDir creates a directory if it is missing, and refuses a path that exists
// as something else.
func EnsureDir(dir string) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return Fail("%s exists and is not a directory.", dir)
		}
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

const maxSuffix = 1000

// freePath returns the first unused name of the form "stem (2).ext".
func freePath(path string) (string, error) {
	if !exists(path) {
		return path, nil
	}
	dir, base := filepath.Split(path)
	stem, ext := splitExt(base)
	for i := 2; i <= maxSuffix; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if !exists(candidate) {
			return candidate, nil
		}
	}
	return "", Fail("could not find a free name next to %s.", path)
}

// splitExt splits on the last dot, so "archive.tar.gz" keeps ".gz" as its
// extension and "archive.tar" as its stem. A leading dot belongs to the stem, so
// ".bashrc" is not treated as an extension.
func splitExt(name string) (stem, ext string) {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name, ""
	}
	return name[:i], name[i:]
}

// SafeFilename turns arbitrary text - a mail subject, say - into a name every
// filesystem the CLI targets will accept.
func SafeFilename(s string) string {
	const maxLen = 120
	var b strings.Builder
	for _, r := range s {
		switch {
		case strings.ContainsRune(`/\:*?"<>|`, r), r < 0x20:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > maxLen {
		out = strings.TrimSpace(out[:maxLen])
	}
	// A trailing dot makes a file unopenable on Windows.
	out = strings.TrimRight(out, ".")
	if out == "" {
		return "download"
	}
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return !errors.Is(err, fs.ErrNotExist)
}

// ReadTextArg resolves a text flag that may be "-", meaning stdin. Centralising
// the convention is what makes `--body -`, `--sieve -`, `--message -` and
// `--signature -` all behave the same.
func ReadTextArg(value, flag string) (string, error) {
	if value != "-" {
		return value, nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", Fail("could not read %s from stdin: %v", flag, err)
	}
	return string(b), nil
}

// Reserve returns the path Write would use, without writing anything.
//
// Streaming downloads need the file open before the bytes arrive, so they cannot
// hand a finished buffer to Write. Reserving keeps them on the same collision
// policy as everything else instead of inventing their own.
func (d *Destination) Reserve(name string) (string, error) {
	if d.output != "" {
		if !d.force && exists(d.output) {
			return "", Fail("%s already exists.", d.output).Hint("--force to overwrite it.")
		}
		return d.output, nil
	}
	if d.outputDir != "" {
		if err := EnsureDir(d.outputDir); err != nil {
			return "", err
		}
	}
	target := filepath.Join(d.outputDir, SafeFilename(name))
	if d.force {
		return target, nil
	}
	return freePath(target)
}

// Dir is the directory a download will land in, for callers that must open a
// temporary file beside the final destination.
//
// It creates the directory, because a caller reaches for it before Reserve has
// had a chance to, and a temporary file cannot be opened in a directory that is
// not there yet.
func (d *Destination) Dir() (string, error) {
	switch {
	case d.output != "":
		dir := filepath.Dir(d.output)
		return dir, EnsureDir(dir)
	case d.outputDir != "":
		return d.outputDir, EnsureDir(d.outputDir)
	}
	return ".", nil
}
