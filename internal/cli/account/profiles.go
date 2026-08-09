package account

import (
	"github.com/roman-16/proton-cli/internal/account/session"
	"github.com/roman-16/proton-cli/internal/cli/kit"
	"github.com/roman-16/proton-cli/internal/ui"
	"github.com/roman-16/proton-cli/internal/units"
	"github.com/spf13/cobra"
)

// A profile is a named session slot on this machine. Two similar-sounding lists
// live under `account`, and the distinction matters: profiles are local, sessions
// are Proton's. Naming both explicitly is clearer than making one of them the
// bare `account list`.

func profilesCmd() *cobra.Command {
	c := &cobra.Command{Use: "profiles", Short: "Accounts signed in on this machine"}
	c.AddCommand(profilesListCmd(), profilesDeleteCmd())
	return c
}

func profilesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the profiles with a saved session",
		Args:  cobra.NoArgs,
		// No authentication: this reads the filesystem, and being able to see
		// which accounts are configured without contacting Proton is the point.
		RunE: kit.Run(nil, func(c *kit.Invocation) error {
			profiles, err := session.Profiles()
			if err != nil {
				return err
			}
			active := c.App.Profile
			return kit.List(c, ui.TableSpec[session.Profile]{
				Noun:  "profiles",
				Total: ui.Unknown, Page: ui.Unpaged,
				Columns: []ui.Column[session.Profile]{
					{Header: "PROFILE", Cell: func(p session.Profile) string { return p.Name }},
					{Header: "EMAIL", Flex: true, Cell: func(p session.Profile) string { return p.Email }},
					{Header: "UNLOCKED", Cell: func(p session.Profile) string { return yesNo(p.Unlocked) }},
					{Header: "SAVED", Cell: func(p session.Profile) string { return units.Time(p.PersistedAt) }},
					{Header: "ACTIVE", Accent: true, Cell: func(p session.Profile) string {
						if p.Name == active {
							return ui.GlyphSuccess
						}
						return ""
					}},
				},
			}, profiles, nil)
		}),
	}
}

func profilesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete REF...",
		Short: "Remove saved sessions by profile name",
		Args:  cobra.MinimumNArgs(1),
		RunE: kit.Run(nil, func(c *kit.Invocation) error {
			names := make([]string, len(c.Args))
			for i, name := range c.Args {
				validated, err := session.NormalizeProfile(name)
				if err != nil {
					return kit.Fail("Invalid profile %q: %v.", name, err)
				}
				names[i] = validated
			}
			return kit.Mutate(c, ui.ResultSpec{
				Action: ui.Deleted, Kind: "profiles", Count: len(names),
				Name: single(names), IDs: names,
			}, func() error {
				for _, name := range names {
					if err := session.Clear(name); err != nil {
						return err
					}
				}
				return nil
			})
		}),
	}
}
