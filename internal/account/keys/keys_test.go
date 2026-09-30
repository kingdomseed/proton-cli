package keys

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtonMail/go-srp"
	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/roman-16/proton-cli/internal/proton"
)

func TestUnlockUsesMatchingSaltAndSavesOnlyWorkingPasswords(t *testing.T) {
	const password = "test-password"
	saltBytes := []byte("0123456789abcdef")
	stretched, err := srp.MailboxPassword([]byte(password), saltBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pgp.GenerateKey("Test", "test@example.com", "x25519", 0)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := key.Lock(stretched[len(stretched)-31:])
	if err != nil {
		t.Fatal(err)
	}
	armored, err := locked.Armor()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{password, "wrong-password"} {
		t.Run(secret, func(t *testing.T) {
			puts := 0
			clientKey := ""
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := map[string]any{"Code": 1000}
				switch r.URL.Path {
				case "/core/v4/users":
					body["User"] = User{ID: "user", Keys: []Key{{ID: "primary", PrivateKey: armored, Active: 1, Primary: 1}}}
				case "/core/v4/addresses":
					body["Addresses"] = []Address{{ID: "address", Keys: []Key{{ID: "address-key", PrivateKey: armored, Active: 1, Primary: 1}}}}
				case "/core/v4/keys/salts":
					body["KeySalts"] = []salt{
						{ID: "secondary", KeySalt: base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))},
						{ID: "primary", KeySalt: base64.StdEncoding.EncodeToString(saltBytes)},
					}
				case "/auth/v4/sessions/local/key":
					if r.Method == http.MethodPut {
						puts++
						var sent struct{ Key string }
						if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
							t.Error(err)
						}
						clientKey = sent.Key
					} else {
						body["ClientKey"] = clientKey
					}
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
				}
				if err := json.NewEncoder(w).Encode(body); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			c := proton.New(proton.Options{BaseURL: srv.URL})
			_, err := Unlock(t.Context(), c, func() (string, error) { return secret, nil })
			if secret != password {
				if err == nil || puts != 0 || c.EncKeyBlob() != "" {
					t.Fatalf("wrong password: err=%v, puts=%d, saved=%t", err, puts, c.EncKeyBlob() != "")
				}
				return
			}
			if err != nil || puts != 1 || c.EncKeyBlob() == "" {
				t.Fatalf("correct password: err=%v, puts=%d, saved=%t", err, puts, c.EncKeyBlob() != "")
			}
			if _, err := Unlock(t.Context(), c, nil); err != nil {
				t.Fatalf("resume without a password: %v", err)
			}
			if puts != 1 {
				t.Errorf("resume rewrote the session key: puts=%d", puts)
			}
		})
	}
}

func unlocked(addrs ...Address) *Unlocked {
	u := &Unlocked{Addresses: addrs, AddrKRs: map[string]*pgp.KeyRing{}}
	for _, a := range addrs {
		if len(a.Keys) > 0 {
			u.AddrKRs[a.ID] = &pgp.KeyRing{}
		}
	}
	return u
}

var withKey = []Key{{ID: "k"}}

func TestFirstAddrSkipsAddressesWithoutKeys(t *testing.T) {
	u := unlocked(
		Address{ID: "locked", Email: "locked@example.com"},
		Address{ID: "open", Email: "open@example.com", DisplayName: "Open", Keys: withKey},
	)
	kr, addr, err := u.FirstAddr()
	if err != nil {
		t.Fatalf("FirstAddr: %v", err)
	}
	if kr == nil {
		t.Error("FirstAddr returned a nil key ring")
	}
	if addr.ID != "open" || addr.DisplayName != "Open" {
		t.Errorf("FirstAddr = %+v, want the address whose keys unlocked", addr)
	}
}

func TestFirstAddrWithoutUnlockableAddresses(t *testing.T) {
	_, _, err := unlocked(Address{ID: "locked", Email: "locked@example.com"}).FirstAddr()
	if err == nil {
		t.Error("FirstAddr with no unlockable address should fail")
	}
}

func TestPrimaryAddrPrefersProtonDomains(t *testing.T) {
	tests := []struct {
		name  string
		addrs []Address
		want  string
	}{
		{
			"custom domain first, proton.me second",
			[]Address{
				{ID: "custom", Email: "me@example.com", Keys: withKey},
				{ID: "proton", Email: "me@proton.me", Keys: withKey},
			},
			"proton",
		},
		{
			"pm.me counts as a Proton domain",
			[]Address{
				{ID: "custom", Email: "me@example.com", Keys: withKey},
				{ID: "pm", Email: "me@pm.me", Keys: withKey},
			},
			"pm",
		},
		{
			"protonmail.com counts as a Proton domain",
			[]Address{
				{ID: "custom", Email: "me@example.com", Keys: withKey},
				{ID: "legacy", Email: "me@protonmail.com", Keys: withKey},
			},
			"legacy",
		},
		{
			"falls back to the first unlockable address",
			[]Address{{ID: "custom", Email: "me@example.com", Keys: withKey}},
			"custom",
		},
		{
			"ignores a Proton address whose keys stayed locked",
			[]Address{
				{ID: "custom", Email: "me@example.com", Keys: withKey},
				{ID: "proton", Email: "me@proton.me"},
			},
			"custom",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, addr, err := unlocked(tc.addrs...).PrimaryAddr()
			if err != nil {
				t.Fatalf("PrimaryAddr: %v", err)
			}
			if addr.ID != tc.want {
				t.Errorf("PrimaryAddr = %q, want %q", addr.ID, tc.want)
			}
		})
	}
}
