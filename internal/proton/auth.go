package proton

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ProtonMail/go-srp"
	"github.com/roman-16/proton-cli/internal/errs"
)

type authInfo struct {
	Code            int
	Modulus         string
	ServerEphemeral string
	Version         int
	Salt            string
	SRPSession      string
}

type authResp struct {
	Code         int
	UID          string
	AccessToken  string
	RefreshToken string
	ServerProof  string
	TwoFA        struct {
		Enabled int
	} `json:"2FA"`
}

// Two-factor methods, as the bitfield Proton returns in 2FA.Enabled.
// Mirrors SETTINGS_2FA_ENABLED in WebClients
// (packages/shared/lib/interfaces/UserSettings.ts).
const (
	twoFAOTP   = 1
	twoFAFIDO2 = 2
)

// TOTPFunc supplies a two-factor code. It is called only when the server says
// the account has TOTP enabled, so an account without two-factor never triggers
// a prompt and a code is never asked for speculatively - which matters, because
// a TOTP is only valid for thirty seconds.
type TOTPFunc func() (string, error)

// Login performs the full web-client auth flow (unauth session → SRP → 2FA).
// On a Proton 9001 (human-verification) response from the SRP step, Login
// consults the installed HVResolver (if any) and retries the auth POST once
// with HV headers, redoing getAuthInfo to obtain a fresh SRPSession.
func (c *Client) Login(ctx context.Context, username string, password []byte, totp TOTPFunc) error {
	sess, err := c.createSession(ctx)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	c.mu.Lock()
	c.uid, c.acc, c.ref = sess.UID, sess.AccessToken, sess.RefreshToken
	c.mu.Unlock()

	auth, err := c.loginSRP(ctx, username, password, "", "")
	var hvErr *HumanVerificationError
	if errors.As(err, &hvErr) {
		if resolver := c.getHVResolver(); resolver != nil {
			token, kind, rerr := resolver(hvErr)
			switch {
			case rerr == nil && token != "":
				auth, err = c.loginSRP(ctx, username, password, token, kind)
			case errors.Is(rerr, ErrHVUnavailable):
				// keep err = hvErr, surfaced below
			case rerr != nil:
				return fmt.Errorf("login: hv resolver: %w", rerr)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	c.mu.Lock()
	c.uid, c.acc, c.ref = auth.UID, auth.AccessToken, auth.RefreshToken
	// The old key blob belongs to the previous session, not the new tokens.
	c.encKeyBlob = ""
	c.mu.Unlock()

	switch {
	case auth.TwoFA.Enabled&twoFAOTP != 0:
		if totp == nil {
			return fmt.Errorf("login: account requires a two-factor code")
		}
		code, err := totp()
		if err != nil {
			return err
		}
		if err := c.auth2FA(ctx, code); err != nil {
			return fmt.Errorf("login: %w", err)
		}
	case auth.TwoFA.Enabled&twoFAFIDO2 != 0:
		// A security key needs a browser to talk WebAuthn, which a terminal has no
		// way to do. Saying so is better than the stream of 401s that would follow
		// a silently half-finished sign-in.
		return errs.Problemf("This account signs in with a security key, which proton-cli cannot use.").
			Hint("add a TOTP authenticator app at https://account.proton.me/mail/account-password,",
				"then sign in with --totp or let proton-cli ask for the code.").Exit(2)
	case auth.TwoFA.Enabled != 0:
		return errs.Problemf("This account uses a two-factor method proton-cli does not support (0x%x).",
			auth.TwoFA.Enabled).Exit(2)
	}
	return nil
}

// srpCall runs one SRP exchange against path within the current session and
// validates the server's proof.
//
// It is the single SRP code path: signing in and elevating a scope differ only
// in which endpoint they call and what they add to the body. Sharing it is what
// guarantees both verify the server's proof, which is the half of SRP that
// authenticates Proton to us.
//
// Mirrors srpAuth in WebClients (packages/shared/lib/srp.ts), whose
// callAndValidate rejects an unexpected server proof for every caller.
func (c *Client) srpCall(
	ctx context.Context,
	method, path, username string,
	password []byte,
	info *authInfo,
	extra map[string]any,
	hvToken, hvType string,
) ([]byte, error) {
	auth, err := srp.NewAuth(info.Version, username, password, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return nil, fmt.Errorf("SRP setup: %w", err)
	}
	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return nil, fmt.Errorf("SRP proofs: %w", err)
	}

	payload := map[string]any{
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"SRPSession":      info.SRPSession,
	}
	for k, v := range extra {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	raw, err := c.rawAuthWithHV(ctx, method, path, body, hvToken, hvType)
	if err != nil {
		return nil, err
	}
	var r struct {
		Code        int
		ServerProof string
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("SRP response parse: %w", err)
	}
	if r.Code != 1000 {
		return nil, parseAuthError(raw, r.Code)
	}
	serverProof, err := base64.StdEncoding.DecodeString(r.ServerProof)
	if err != nil {
		return nil, fmt.Errorf("server proof decode: %w", err)
	}
	if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		return nil, fmt.Errorf("server proof verification failed")
	}
	return raw, nil
}

func (c *Client) createSession(ctx context.Context) (*authResp, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.base+"/auth/v4/sessions", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setClientHeaders(req)
	req.Header.Set("x-enforce-unauthsession", "true")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &NetworkError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := readAuthResponse(resp)
	if err != nil {
		return nil, err
	}
	var r authResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("session parse: %w", err)
	}
	if r.Code != 1000 {
		return nil, parseAuthError(b, r.Code)
	}
	return &r, nil
}

// getAuthInfo fetches the SRP parameters for username.
//
// Intent identifies the sign-in flow, and ReauthScope tells the server which
// elevation the following exchange is for; both are what the web clients send
// (packages/shared/lib/api/auth.ts getInfo). reauthScope is empty for a fresh
// sign-in.
func (c *Client) getAuthInfo(ctx context.Context, username string, reauthScope Scope) (*authInfo, error) {
	payload := map[string]any{"Intent": "Proton"}
	if username != "" {
		payload["Username"] = username
	}
	if reauthScope != "" {
		payload["ReauthScope"] = string(reauthScope)
	}
	body, _ := json.Marshal(payload)
	raw, err := c.rawAuth(ctx, "POST", "/core/v4/auth/info", body)
	if err != nil {
		return nil, err
	}
	var r authInfo
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("auth info parse: %w", err)
	}
	if r.Code != 1000 {
		return nil, parseAuthError(raw, r.Code)
	}
	return &r, nil
}

// loginSRP runs getAuthInfo + the SRP POST /auth in one shot. When
// hvToken/hvType are non-empty they're attached as HV headers on the auth POST.
func (c *Client) loginSRP(ctx context.Context, username string, password []byte, hvToken, hvType string) (*authResp, error) {
	info, err := c.getAuthInfo(ctx, username, "")
	if err != nil {
		return nil, err
	}
	raw, err := c.srpCall(ctx, "POST", "/core/v4/auth", username, password, info,
		map[string]any{"Username": username}, hvToken, hvType)
	if err != nil {
		return nil, err
	}
	var r authResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("auth parse: %w", err)
	}
	return &r, nil
}

func (c *Client) auth2FA(ctx context.Context, totp string) error {
	body, _ := json.Marshal(map[string]string{"TwoFactorCode": totp})
	raw, err := c.rawAuth(ctx, "POST", "/core/v4/auth/2fa", body)
	if err != nil {
		return err
	}
	var r struct{ Code int }
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("2FA parse: %w", err)
	}
	if r.Code != 1000 {
		return parseAuthError(raw, r.Code)
	}
	return nil
}

// rawAuth sends a request with current session headers and returns the body.
// Used for auth-flow endpoints that bypass the normal Do retry path.
func (c *Client) rawAuth(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	return c.rawAuthWithHV(ctx, method, path, body, "", "")
}

func (c *Client) rawAuthWithHV(ctx context.Context, method, path string, body []byte, hvToken, hvType string) ([]byte, error) {
	c.mu.RLock()
	uid, acc := c.uid, c.acc
	c.mu.RUnlock()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setClientHeaders(req)
	if uid != "" {
		req.Header.Set("x-pm-uid", uid)
	}
	if acc != "" {
		req.Header.Set("Authorization", "Bearer "+acc)
	}
	if hvToken != "" && hvType != "" {
		req.Header.Set("x-pm-human-verification-token", hvToken)
		req.Header.Set("x-pm-human-verification-token-type", hvType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &NetworkError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	return readAuthResponse(resp)
}

// readAuthResponse checks the status before parsing an authentication response.
func readAuthResponse(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		hv, apiErr := classifyErrorBody(resp.StatusCode, body)
		if hv != nil {
			return nil, hv
		}
		return nil, apiErr
	}
	return body, nil
}
