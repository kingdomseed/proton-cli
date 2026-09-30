//go:build !windows

package kit

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAForcedWriteIsPrivateOverAReadableFile(t *testing.T) {
	for _, c := range []struct {
		name string
		dest func(dir, path string) *Destination
	}{
		{"a named path", func(_, path string) *Destination { return &Destination{output: path, force: true} }},
		{"a directory", func(dir, _ string) *Destination { return &Destination{outputDir: dir, force: true} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secrets.json")
			write(t, path, "old")
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}

			if _, err := c.dest(dir, path).Write(nil, "secrets.json", []byte("new")); err != nil {
				t.Fatal(err)
			}

			fi, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("left the export readable: %v", fi.Mode().Perm())
			}
			if got := read(t, path); got != "new" {
				t.Errorf("wrote %q", got)
			}
		})
	}
}

func TestAForcedWriteReplacesALinkRatherThanFollowingIt(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	write(t, elsewhere, "untouched")
	path := filepath.Join(dir, "export.json")
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}

	d := &Destination{output: path, force: true}
	if _, err := d.Write(nil, "ignored", []byte("new")); err != nil {
		t.Fatal(err)
	}

	if got := read(t, elsewhere); got != "untouched" {
		t.Errorf("followed the link and wrote %q through it", got)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the destination is still a link")
	}
	if got := read(t, path); got != "new" {
		t.Errorf("wrote %q", got)
	}
}

func TestAStreamedWriteIsPrivate(t *testing.T) {
	dir := t.TempDir()
	d := &Destination{outputDir: dir}

	path, err := d.WriteStream(nil, "photo.jpg", func(w io.Writer) error {
		_, err := io.WriteString(w, "bytes")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("left the download readable: %v", fi.Mode().Perm())
	}
}
