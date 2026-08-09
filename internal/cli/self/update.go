package self

import (
	"fmt"
	"github.com/roman-16/proton-cli/internal/cli/kit"
	"net/http"
	"strings"
	"time"

	"github.com/roman-16/proton-cli/internal/selfmanage"
	"github.com/spf13/cobra"
)

// UpdateCmd replaces this binary in place with a published release.
func UpdateCmd(version string) *cobra.Command {
	var checkOnly, reinstall bool
	cmd := &cobra.Command{
		Use:     "update [version]",
		Aliases: []string{"upgrade", "self-update"},
		Short:   "Update proton-cli to the latest release",
		Long: `Replace this proton-cli binary in place with the latest GitHub release
(or a specific version), verifying the download against the published
SHA-256 checksums.

Only a curl-script install or a manually downloaded binary can update
itself. If proton-cli was installed with a package manager (apt, dnf,
apk, Homebrew, winget, npm, Nix), update it with that package manager.

Examples:
  proton-cli update             # update to the latest release
  proton-cli update --check     # report whether an update is available
  proton-cli update 1.9.11      # install a specific version
  proton-cli update --reinstall # install the latest even if up to date`,
		Args: cobra.MaximumNArgs(1),
		RunE: kit.Run(nil, func(c *kit.Invocation) error {
			target := ""
			if len(c.Args) == 1 {
				target = strings.TrimPrefix(c.Args[0], "v")
			}
			return runUpdate(c, version, target, checkOnly, reinstall)
		}),
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Only report whether an update is available; don't install")
	cmd.Flags().BoolVar(&reinstall, "reinstall", false, "Install again even if already up to date")
	return cmd
}

type updateStatus struct {
	Current         string `json:"current"`
	Latest          string `json:"latest"`
	UpdateAvailable bool   `json:"update_available"`
}

func runUpdate(c *kit.Invocation, version, target string, checkOnly, reinstall bool) error {
	u := c.UI()
	client := &http.Client{Timeout: 60 * time.Second}
	if !checkOnly && !selfmanage.SignedUpdatesEnabled {
		return fmt.Errorf("self-update is disabled because release checksums do not have an independent signature; build and install this fork locally")
	}

	latest := target
	if latest == "" {
		v, err := selfmanage.LatestVersion(c.Ctx, client)
		if err != nil {
			return fmt.Errorf("resolve latest version: %w", err)
		}
		latest = v
	}
	newer := selfmanage.IsNewer(latest, version)

	if checkOnly {
		if u.Format.Machine() {
			return kit.Object(c, updateStatus{Current: version, Latest: latest, UpdateAvailable: newer})
		}
		if newer {
			u.Note(fmt.Sprintf("Update available: %s -> %s. Run `proton-cli update` to install it.", version, latest))
		} else {
			u.Note(fmt.Sprintf("proton-cli is up to date (%s).", version))
		}
		return nil
	}

	if version == "dev" && target == "" && !reinstall {
		return fmt.Errorf("this is a development build with no version to compare; install a release " +
			"(see the README's curl install) or pass an explicit version, e.g. `proton-cli update 1.9.11`")
	}

	if !newer && target == "" && !reinstall {
		if u.Format.Machine() {
			return kit.Object(c, updateStatus{Current: version, Latest: latest, UpdateAvailable: false})
		}
		u.Note(fmt.Sprintf("proton-cli is already up to date (%s).", version))
		return nil
	}

	exe, err := resolveExe()
	if err != nil {
		return err
	}
	if err := guardManaged(exe, actionUpdate); err != nil {
		return err
	}

	u.Note(fmt.Sprintf("Downloading proton-cli %s...", latest))
	bin, err := selfmanage.Download(c.Ctx, client, latest)
	if err != nil {
		return err
	}
	u.Note("Verified checksum. Installing...")
	if err := selfmanage.Apply(bin, exe); err != nil {
		return selfManageError(err, exe, actionUpdate)
	}

	if u.Format.Machine() {
		return kit.Object(c, updateStatus{Current: latest, Latest: latest, UpdateAvailable: false})
	}
	u.Note(fmt.Sprintf("Updated proton-cli %s -> %s.", version, latest))
	return nil
}
