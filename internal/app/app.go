// Package app wires the Proton services, renderer and session together for
// the CLI. One App instance per invocation.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/account/session"
	"github.com/roman-16/proton-cli/internal/idcache"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/service/account"
	"github.com/roman-16/proton-cli/internal/service/calendar"
	"github.com/roman-16/proton-cli/internal/service/contacts"
	"github.com/roman-16/proton-cli/internal/service/drive"
	"github.com/roman-16/proton-cli/internal/service/mail"
	"github.com/roman-16/proton-cli/internal/service/pass"
	"github.com/roman-16/proton-cli/internal/ui"
)

type App struct {
	Profile string
	// Creds resolves the account email, password and two-factor code, asking the
	// user only when nothing else supplies them.
	Creds *Credentials

	API *proton.Client

	Account  *account.Service
	Mail     *mail.Service
	Drive    *drive.Service
	Calendar *calendar.Service
	Contacts *contacts.Service
	Pass     *pass.Service

	// UI renders everything the command produces.
	UI *ui.UI

	DryRun  bool
	FullIDs bool
	// Yes answers every confirmation in advance, for scripts that mean it.
	Yes bool

	IDCache *idcache.Cache

	// HVUnavailableDetail is a one-line diagnostic the HV resolver may stash
	// when it returns proton.ErrHVUnavailable; the cli final-error formatter
	// surfaces it.
	HVUnavailableDetail string

	mu    sync.Mutex
	cache *keys.Unlocked

	sessionMu sync.Mutex
	userID    string
	email     string
}

type Options struct {
	Profile    string
	User       string
	Password   string
	TOTP       string
	APIURL     string
	AppVersion string
	Version    string
	Output     ui.Format
	LogLevel   slog.Level
	Quiet      bool
	DryRun     bool
	FullIDs    bool
	NoColor    bool
	NoInput    bool
	Yes        bool
}

func New(opts Options) (*App, error) {
	profileName, err := session.NormalizeProfile(firstNonEmpty(opts.Profile, os.Getenv("PROTON_PROFILE"), "default"))
	if err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}

	apiURL := firstNonEmpty(opts.APIURL, envForProfile(profileName, "API_URL"))
	appVer := firstNonEmpty(opts.AppVersion, envForProfile(profileName, "APP_VERSION"))
	userAgent := defaultUserAgent(opts.Version)

	u := ui.New(ui.Options{
		Format:   opts.Output,
		LogLevel: opts.LogLevel,
		Quiet:    opts.Quiet,
		NoColor:  opts.NoColor,
		NoInput:  opts.NoInput,
		FullIDs:  opts.FullIDs,
	})
	c := proton.New(proton.Options{
		AppVersion: appVer, BaseURL: apiURL, Logger: u.Log, Profile: profileName, UserAgent: userAgent,
	})

	var userID, email string
	if sess, err := session.Load(profileName); err == nil && sess != nil {
		c.SetTokens(sess.UID, sess.AccessToken, sess.RefreshToken)
		c.SetEncKeyBlob(sess.EncKeyBlob)
		userID, email = sess.UserID, sess.Email
	}

	a := &App{
		Profile:  profileName,
		Creds:    newCredentials(profileName, u, opts.User, opts.Password, opts.TOTP),
		API:      c,
		Account:  account.New(c),
		Mail:     mail.New(c),
		Drive:    drive.New(c),
		Calendar: calendar.New(c),
		Contacts: contacts.New(c),
		Pass:     pass.New(c),
		UI:       u,
		DryRun:   opts.DryRun,
		FullIDs:  opts.FullIDs,
		Yes:      opts.Yes,
		IDCache:  idcache.New(idCachePath(profileName)),
		userID:   userID,
		email:    email,
	}
	// The client persists the session file whenever its tokens change (e.g. a
	// mid-request refresh); it stays free of the persistence format by calling
	// back into saveSession, which owns the DTO assembly.
	c.SetPersistHook(func() { _ = a.saveSession() })
	a.installScopeResolver()
	return a, nil
}

// saveSession writes the current client state to the profile's session file,
// preserving the identity fields an earlier save established. Those come from
// /core/v4/users, which the client has no business fetching, so they are set
// once by rememberIdentity and carried forward from here on.
func (a *App) saveSession() error {
	uid, acc, refresh := a.API.Tokens()
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	return session.Save(a.Profile, &session.Session{
		UID:          uid,
		AccessToken:  acc,
		RefreshToken: refresh,
		UserID:       a.userID,
		Email:        a.email,
		EncKeyBlob:   a.API.EncKeyBlob(),
		AppVersion:   a.API.AppVersion(),
		BaseURL:      a.API.BaseURL(),
	})
}

// rememberIdentity records who the session belongs to, so listing profiles can
// name each account without one API call per profile.
func (a *App) rememberIdentity(userID, email string) {
	a.sessionMu.Lock()
	a.userID, a.email = userID, email
	a.sessionMu.Unlock()
}

// idCachePath mirrors the session-file convention.
func idCachePath(profile string) string {
	if profile == "" {
		profile = "default"
	}
	cd, err := os.UserConfigDir()
	if err != nil {
		cd = "."
	}
	return filepath.Join(cd, "proton-cli", "idcache", profile+".json")
}

// Authenticate makes sure the client holds a usable session, signing in when it
// does not. It is a no-op once a session exists, which is why a saved session
// means later commands never ask for anything.
func (a *App) Authenticate(ctx context.Context) error {
	if uid, _, _ := a.API.Tokens(); uid != "" {
		return nil
	}
	return a.Login(ctx)
}

// Login signs in and saves the session, replacing any existing one.
//
// It also unlocks the key hierarchy, which seals the key password into the
// session file. Doing both here is what makes the password a one-time cost: a
// login that only stored tokens would leave the very next command asking again.
func (a *App) Login(ctx context.Context) error {
	user, err := a.Creds.User()
	if err != nil {
		return err
	}
	password, err := a.Creds.Password("sign in")
	if err != nil {
		return err
	}
	if err := a.API.Login(ctx, user, []byte(password), a.Creds.TOTP); err != nil {
		return err
	}
	if err := a.saveSession(); err != nil {
		return err
	}
	if _, err := a.Unlock(ctx); err != nil {
		return err
	}
	return a.saveSession()
}

// Unlock returns the decrypted key hierarchy, memoised for the invocation.
//
// The password is requested lazily, and only on the path that actually needs it:
// once the session file carries the sealed key password, unlocking asks for
// nothing at all.
func (a *App) Unlock(ctx context.Context) (*keys.Unlocked, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache != nil {
		return a.cache, nil
	}
	u, err := keys.Unlock(ctx, a.API, func() (string, error) {
		return a.Creds.Password("unlock your keys")
	})
	if err != nil {
		return nil, err
	}
	a.cache = u
	return u, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// defaultUserAgent honestly identifies the CLI in the User-Agent header, e.g.
// "proton-cli/1.2.3".
func defaultUserAgent(version string) string {
	if version == "" {
		version = "dev"
	}
	return "proton-cli/" + version
}

// RememberIdentity records who the current session belongs to. Exported for the
// account commands, which learn it from /core/v4/users after signing in.
func (a *App) RememberIdentity(userID, email string) { a.rememberIdentity(userID, email) }

// SaveSession writes the current session state to disk.
func (a *App) SaveSession() error { return a.saveSession() }
