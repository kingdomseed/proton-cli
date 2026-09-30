package mail

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/ui"
)

func TestAutoReplyDryRunChecksScheduleWithoutSigningIn(t *testing.T) {
	for _, end := range []string{"2026-10-01T08:00", "2026-10-01T10:00"} {
		t.Run(end, func(t *testing.T) {
			var out, notes bytes.Buffer
			u := ui.New(ui.Options{Format: ui.FormatText, Out: &out, Err: &notes, NoColor: true, NoInput: true})
			a := &app.App{API: proton.New(proton.Options{}), UI: u, DryRun: true}
			cmd := autoreplySetCmd()
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			cmd.SetArgs([]string{"--start", "2026-10-01T09:00", "--end", end, "--zone", "UTC", "--message", "away"})
			err := cmd.ExecuteContext(app.WithApp(context.Background(), a))
			if end == "2026-10-01T08:00" {
				if err == nil || !strings.Contains(err.Error(), "end") {
					t.Fatalf("invalid schedule: %v", err)
				}
				if strings.Contains(notes.String(), "Dry run") {
					t.Error("invalid schedule was reported as a successful dry run")
				}
			} else if err != nil || !strings.Contains(notes.String(), "Dry run") {
				t.Fatalf("valid dry run: err=%v, notes=%q", err, notes.String())
			}
		})
	}
}
