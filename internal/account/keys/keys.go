// Package keys unlocks the Proton user/address/key hierarchy for a session.
package keys

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ProtonMail/go-srp"
	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/roman-16/proton-cli/internal/account/localkey"
	"github.com/roman-16/proton-cli/internal/proton"
)

type Unlocked struct {
	UserKR    *pgp.KeyRing
	AddrKRs   map[string]*pgp.KeyRing
	Addresses []Address
}

type User struct {
	ID   string
	Name string
	Keys []Key
}

// Address mirrors the fields of /core/v4/addresses the CLI needs. Order,
// Status, Send and Receive drive sender selection: Proton only allows sending
// from an address that is active and both sendable and receivable, and presents
// them in Order.
type Address struct {
	ID          string
	Email       string
	DisplayName string
	Signature   string
	Order       int
	Status      int
	Send        int
	Receive     int
	Type        int
	Keys        []Key
}

// CanSend reports whether Proton permits composing from this address.
func (a Address) CanSend() bool {
	return a.Status == 1 && a.Send == 1 && a.Receive == 1
}

type Key struct {
	ID         string
	PrivateKey string
	Token      string
	Signature  string
	Primary    int
	Active     int
}

type salt struct {
	ID      string
	KeySalt string
}

// PasswordFunc supplies the account password. It is called only when the session
// carries no sealed key password, so a resumed session unlocks without asking
// for anything.
type PasswordFunc func() (string, error)

// Unlock fetches the user and address keys and unlocks them, using either the
// key password sealed into the session or, on a first unlock, one derived from
// the account password.
func Unlock(ctx context.Context, c *proton.Client, password PasswordFunc) (*Unlocked, error) {
	user, err := getUser(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	var skp string
	if c.EncKeyBlob() != "" {
		// Resume: recover the key password by unwrapping the on-disk blob with the
		// server-held client key. A failure here (e.g. the session was revoked) is
		// fatal - the blob is useless without the key.
		key, err := localkey.Get(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("fetch session key: %w", err)
		}
		d, err := localkey.Unwrap(c.EncKeyBlob(), key)
		if err != nil {
			return nil, fmt.Errorf("decrypt session key blob: %w", err)
		}
		skp = d
	} else {
		// First unlock: derive from the account password. Save it after the keys open.
		if password == nil {
			return nil, fmt.Errorf("no password available to unlock the keys")
		}
		pw, err := password()
		if err != nil {
			return nil, err
		}
		d, err := deriveSaltedKeyPass(ctx, c, user.Keys, pw)
		if err != nil {
			return nil, fmt.Errorf("derive key password: %w", err)
		}
		skp = d
	}

	userKR, err := unlockKeyRing(user.Keys, []byte(skp), nil)
	if err != nil {
		return nil, fmt.Errorf("unlock user keys: %w", err)
	}

	addrs, err := getAddresses(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}
	addrKRs := map[string]*pgp.KeyRing{}
	for _, a := range addrs {
		if kr, err := unlockKeyRing(a.Keys, []byte(skp), userKR); err == nil {
			addrKRs[a.ID] = kr
		}
	}
	if len(addrKRs) == 0 {
		return nil, fmt.Errorf("failed to unlock any address keys")
	}
	if c.EncKeyBlob() == "" {
		wrapAndPersist(ctx, c, skp)
	}
	return &Unlocked{UserKR: userKR, AddrKRs: addrKRs, Addresses: addrs}, nil
}

// wrapAndPersist generates a fresh client key, stores it server-side, wraps the
// salted key password with it, and rewrites the session file in encrypted form.
// Best-effort: skp is already held in memory for this run, so a failure here
// never fails the unlock - it only defers persistence to the next run.
func wrapAndPersist(ctx context.Context, c *proton.Client, skp string) {
	key, err := localkey.Generate()
	if err != nil {
		slog.Debug("localkey: generate failed; key password not persisted this run", "err", err)
		return
	}
	if err := localkey.Put(ctx, c, key); err != nil {
		slog.Debug("localkey: put failed; key password not persisted this run", "err", err)
		return
	}
	blob, err := localkey.Wrap(skp, key)
	if err != nil {
		slog.Debug("localkey: wrap failed; key password not persisted this run", "err", err)
		return
	}
	c.SetEncKeyBlob(blob)
	c.Persist()
}

// PrimaryAddr returns the key ring and address record for the user's primary
// proton.me/pm.me address, falling back to the first unlockable address.
func (u *Unlocked) PrimaryAddr() (*pgp.KeyRing, Address, error) {
	for _, a := range u.Addresses {
		if kr, ok := u.AddrKRs[a.ID]; ok {
			e := a.Email
			if strings.HasSuffix(e, "@proton.me") || strings.HasSuffix(e, "@pm.me") || strings.HasSuffix(e, "@protonmail.com") {
				return kr, a, nil
			}
		}
	}
	return u.FirstAddr()
}

// FirstAddr returns the key ring and address record of the first address whose
// keys could be unlocked.
func (u *Unlocked) FirstAddr() (*pgp.KeyRing, Address, error) {
	for _, a := range u.Addresses {
		if kr, ok := u.AddrKRs[a.ID]; ok {
			return kr, a, nil
		}
	}
	return nil, Address{}, fmt.Errorf("no address key rings available")
}

func (u *Unlocked) AddrKR(addrID string) (*pgp.KeyRing, bool) {
	kr, ok := u.AddrKRs[addrID]
	return kr, ok
}

func deriveSaltedKeyPass(ctx context.Context, c *proton.Client, keys []Key, password string) (string, error) {
	var r struct{ KeySalts []salt }
	if err := c.Decode(ctx, proton.Request{Method: "GET", Path: "/core/v4/keys/salts"}, &r); err != nil {
		return "", err
	}
	keySalt := saltOf(keys, r.KeySalts)
	if keySalt == "" {
		return password, nil
	}
	ks, err := base64.StdEncoding.DecodeString(keySalt)
	if err != nil {
		return "", err
	}
	sp, err := srp.MailboxPassword([]byte(password), ks)
	if err != nil {
		return "", err
	}
	return string(sp[len(sp)-31:]), nil
}

// saltOf matches the primary user key, which Proton returns first, to its salt.
// Legacy keys without a salt use the password directly.
func saltOf(keys []Key, salts []salt) string {
	if len(keys) == 0 {
		return ""
	}
	for _, s := range salts {
		if s.ID == keys[0].ID {
			return s.KeySalt
		}
	}
	return ""
}

func getUser(ctx context.Context, c *proton.Client) (*User, error) {
	var r struct{ User User }
	if err := c.Decode(ctx, proton.Request{Method: "GET", Path: "/core/v4/users"}, &r); err != nil {
		return nil, err
	}
	return &r.User, nil
}

func getAddresses(ctx context.Context, c *proton.Client) ([]Address, error) {
	var r struct{ Addresses []Address }
	if err := c.Decode(ctx, proton.Request{Method: "GET", Path: "/core/v4/addresses"}, &r); err != nil {
		return nil, err
	}
	return r.Addresses, nil
}

func unlockKeyRing(keys []Key, passphrase []byte, userKR *pgp.KeyRing) (*pgp.KeyRing, error) {
	kr, err := pgp.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Active == 0 {
			continue
		}
		secret := passphrase
		if k.Token != "" && k.Signature != "" && userKR != nil {
			s, err := decryptToken(k.Token, k.Signature, userKR)
			if err != nil {
				continue
			}
			secret = s
		}
		locked, err := pgp.NewKeyFromArmored(k.PrivateKey)
		if err != nil {
			continue
		}
		unlocked, err := locked.Unlock(secret)
		if err != nil {
			continue
		}
		_ = kr.AddKey(unlocked)
	}
	if kr.CountEntities() == 0 {
		return nil, fmt.Errorf("no keys could be unlocked")
	}
	return kr, nil
}

func decryptToken(tokenArm, sigArm string, kr *pgp.KeyRing) ([]byte, error) {
	msg, err := pgp.NewPGPMessageFromArmored(tokenArm)
	if err != nil {
		return nil, err
	}
	sig, err := pgp.NewPGPSignatureFromArmored(sigArm)
	if err != nil {
		return nil, err
	}
	dec, err := kr.Decrypt(msg, nil, 0)
	if err != nil {
		return nil, err
	}
	if err := kr.VerifyDetached(dec, sig, 0); err != nil {
		return nil, err
	}
	return dec.GetBinary(), nil
}
