package proton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/go-srp"
)

func TestAuthReportsHTTPFailures(t *testing.T) {
	for _, stage := range []string{"session", "auth info", "two-factor code"} {
		t.Run(stage, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("<html>gateway failed</html>"))
			}))
			defer srv.Close()
			c := New(Options{BaseURL: srv.URL})
			var err error
			switch stage {
			case "session":
				_, err = c.createSession(t.Context())
			case "auth info":
				_, err = c.getAuthInfo(t.Context(), "user", "")
			case "two-factor code":
				err = c.auth2FA(t.Context(), "123456")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.HTTPStatus != 502 || apiErr.ExitCode() != 5 {
				t.Fatalf("error = %v, want HTTP 502 with exit code 5", err)
			}
			if strings.Contains(err.Error(), "<html>") {
				t.Error("error exposed the response body")
			}
		})
	}
}

func TestLoginDropsPreviousSessionKey(t *testing.T) {
	for _, withTwoFA := range []bool{false, true} {
		name := "password"
		if withTwoFA {
			name = "password and two-factor code"
		}
		t.Run(name, func(t *testing.T) {
			const username, password = "test-user", "test-password"
			salt := []byte("0123456789")
			auth, err := srp.NewAuthForVerifier([]byte(password), loginTestModulus, salt)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := auth.GenerateVerifier(2048)
			if err != nil {
				t.Fatal(err)
			}
			server, err := srp.NewServerFromSigned(loginTestModulus, verifier, 2048)
			if err != nil {
				t.Fatal(err)
			}
			ephemeral, err := server.GenerateChallenge()
			if err != nil {
				t.Fatal(err)
			}
			twoFARequests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var response any
				switch r.Method + " " + r.URL.Path {
				case "POST /auth/v4/sessions":
					response = map[string]any{"Code": 1000, "UID": "anonymous", "AccessToken": "anon-access", "RefreshToken": "anon-refresh"}
				case "POST /core/v4/auth/info":
					response = map[string]any{
						"Code": 1000, "Version": 4, "Salt": base64.StdEncoding.EncodeToString(salt),
						"Modulus": loginTestModulus, "ServerEphemeral": base64.StdEncoding.EncodeToString(ephemeral), "SRPSession": "test-srp",
					}
				case "POST /core/v4/auth":
					var body struct{ ClientEphemeral, ClientProof string }
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					clientEphemeral, err := base64.StdEncoding.DecodeString(body.ClientEphemeral)
					if err != nil {
						t.Error(err)
						return
					}
					clientProof, err := base64.StdEncoding.DecodeString(body.ClientProof)
					if err != nil {
						t.Error(err)
						return
					}
					proof, err := server.VerifyProofs(clientEphemeral, clientProof)
					if err != nil {
						t.Error(err)
						return
					}
					enabled := 0
					if withTwoFA {
						enabled = twoFAOTP
					}
					response = map[string]any{
						"Code": 1000, "UID": "new-session", "AccessToken": "new-access", "RefreshToken": "new-refresh",
						"ServerProof": base64.StdEncoding.EncodeToString(proof), "2FA": map[string]any{"Enabled": enabled},
					}
				case "POST /core/v4/auth/2fa":
					twoFARequests++
					response = map[string]any{"Code": 1000}
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()

			c := New(Options{BaseURL: srv.URL})
			c.SetTokens("old-session", "old-access", "old-refresh")
			c.SetEncKeyBlob("blob-from-old-session")
			if err := c.Login(context.Background(), username, []byte(password), func() (string, error) {
				return "123456", nil
			}); err != nil {
				t.Fatalf("Login: %v", err)
			}
			if uid, acc, ref := c.Tokens(); uid != "new-session" || acc != "new-access" || ref != "new-refresh" {
				t.Errorf("tokens = %q, %q, %q, want the new session", uid, acc, ref)
			}
			if c.EncKeyBlob() != "" {
				t.Error("login kept a key blob that belongs to the old session")
			}
			wantTwoFA := 0
			if withTwoFA {
				wantTwoFA = 1
			}
			if twoFARequests != wantTwoFA {
				t.Errorf("two-factor requests = %d, want %d", twoFARequests, wantTwoFA)
			}
		})
	}
}

// Public signed modulus from ProtonMail/go-srp v0.0.7 (MIT license).
const loginTestModulus = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----`
