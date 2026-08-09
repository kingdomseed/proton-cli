package kit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The collision policy is the interesting part, and it differs by intent on
// purpose: a path the user named is never replaced silently, while a name the CLI
// chose itself may be adjusted.
func TestDestinationCollisionPolicy(t *testing.T) {
	t.Run("an explicit path is refused when it exists", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "report.pdf")
		write(t, path, "original")

		d := &Destination{output: path}
		_, err := d.Write(nil, "ignored", []byte("new"))
		if err == nil {
			t.Fatal("want a refusal, got none")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("unhelpful message: %v", err)
		}
		if got := read(t, path); got != "original" {
			t.Errorf("the existing file was touched: %q", got)
		}
	})

	t.Run("--force replaces it", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "report.pdf")
		write(t, path, "original")

		d := &Destination{output: path, force: true}
		got, err := d.Write(nil, "ignored", []byte("new"))
		if err != nil {
			t.Fatal(err)
		}
		if got != path {
			t.Errorf("wrote to %q, want %q", got, path)
		}
		if read(t, path) != "new" {
			t.Error("--force should have replaced the contents")
		}
	})

	t.Run("a chosen name gets a suffix instead", func(t *testing.T) {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "report.pdf"), "first")

		d := &Destination{outputDir: dir}
		got, err := d.Write(nil, "report.pdf", []byte("second"))
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(dir, "report (2).pdf")
		if got != want {
			t.Errorf("wrote to %q, want %q", got, want)
		}
		if read(t, filepath.Join(dir, "report.pdf")) != "first" {
			t.Error("the first file should be untouched")
		}
	})

	t.Run("suffixes keep counting", func(t *testing.T) {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "a.txt"), "1")
		write(t, filepath.Join(dir, "a (2).txt"), "2")

		d := &Destination{outputDir: dir}
		got, err := d.Write(nil, "a.txt", []byte("3"))
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(dir, "a (3).txt"); got != want {
			t.Errorf("wrote to %q, want %q", got, want)
		}
	})
}

func TestWriteStreamCommitsOnlyCompleteOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "mail.mbox")
	d := &Destination{output: target}
	got, err := d.WriteStream(nil, "ignored", func(w io.Writer) error {
		if _, err := io.WriteString(w, "first"); err != nil {
			return err
		}
		_, err := io.WriteString(w, " second")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != target || read(t, target) != "first second" {
		t.Errorf("WriteStream wrote %q to %q", read(t, target), got)
	}

	failedTarget := filepath.Join(dir, "failed.mbox")
	d = &Destination{output: failedTarget}
	_, err = d.WriteStream(nil, "ignored", func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return errors.New("stop")
	})
	if err == nil {
		t.Fatal("WriteStream ignored the producer error")
	}
	if exists(failedTarget) {
		t.Error("WriteStream left a partial final file")
	}
}

// A double extension keeps the part that identifies the format.
func TestSplitExt(t *testing.T) {
	for _, tc := range []struct{ in, stem, ext string }{
		{"report.pdf", "report", ".pdf"},
		{"archive.tar.gz", "archive.tar", ".gz"},
		{"README", "README", ""},
		{".bashrc", ".bashrc", ""},
	} {
		stem, ext := splitExt(tc.in)
		if stem != tc.stem || ext != tc.ext {
			t.Errorf("splitExt(%q) = (%q, %q), want (%q, %q)", tc.in, stem, ext, tc.stem, tc.ext)
		}
	}
}

func TestValidateRejectsImpossibleCombinations(t *testing.T) {
	t.Run("both destinations", func(t *testing.T) {
		d := &Destination{output: "a", outputDir: "b"}
		if err := d.Validate(true); err == nil {
			t.Error("want a refusal")
		}
	})
	t.Run("one file for many items", func(t *testing.T) {
		d := &Destination{output: "a"}
		if err := d.Validate(false); err == nil {
			t.Error("want a refusal")
		}
	})
	t.Run("stdout for many items", func(t *testing.T) {
		d := &Destination{output: "-"}
		if err := d.Validate(false); err == nil {
			t.Error("several files down one stream is one unusable run of bytes")
		}
	})
	t.Run("stdout for one item", func(t *testing.T) {
		d := &Destination{output: "-"}
		if err := d.Validate(true); err != nil {
			t.Errorf("one item is exactly what a stream carries: %v", err)
		}
	})
}

// A mail subject becomes a file name on every platform the CLI targets, which
// means losing the characters Windows forbids and anything that would escape the
// directory.
func TestSafeFilename(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Invoice #2291 is ready", "Invoice #2291 is ready"},
		{"Re: budget/2026", "Re budget 2026"},
		{`a"b<c>d|e?f*g:h\i`, "a b c d e f g h i"},
		{"  collapsed   spaces  ", "collapsed spaces"},
		{"trailing dots...", "trailing dots"},
		{"", "download"},
		{"../../etc/passwd", ".. .. etc passwd"},
	} {
		if got := SafeFilename(tc.in); got != tc.want {
			t.Errorf("SafeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if n := len(SafeFilename(strings.Repeat("x", 500))); n > 120 {
		t.Errorf("length not capped: %d", n)
	}
}

// --output-dir names where the bytes go, so a directory that is not there yet is
// a request to make it. Photo downloads open a temporary file in it before
// anything else does, which is where this used to give way.
func TestDirCreatesTheDestination(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "pics", "2026")
	d := &Destination{outputDir: nested}

	got, err := d.Dir()
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if got != nested {
		t.Errorf("got %q want %q", got, nested)
	}
	if fi, err := os.Stat(nested); err != nil || !fi.IsDir() {
		t.Errorf("%s was not created: %v", nested, err)
	}
	if _, err := os.CreateTemp(got, ".probe-*"); err != nil {
		t.Errorf("a temporary file cannot be opened there: %v", err)
	}
}

// A file where the directory should be is a mistake worth naming, not a stack of
// permission errors later on.
func TestDirRefusesAPathThatIsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir")
	write(t, path, "x")

	if _, err := (&Destination{outputDir: path}).Dir(); err == nil {
		t.Fatal("want an error for a destination that is a file")
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
