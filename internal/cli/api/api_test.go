package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/app"
	"github.com/roman-16/proton-cli/internal/proton"
	"github.com/roman-16/proton-cli/internal/ui"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestReadOnlyMethod(t *testing.T) {
	for _, method := range []string{"GET", "get", "HEAD", "OPTIONS"} {
		if !readOnlyMethod(method) {
			t.Errorf("%s should be read-only", method)
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "PROPFIND"} {
		if readOnlyMethod(method) {
			t.Errorf("%s should be treated as mutating", method)
		}
	}
}

func TestDryRunDoesNotSendMutatingRawRequest(t *testing.T) {
	var out, errOut bytes.Buffer
	renderer := ui.New(ui.Options{Format: ui.FormatText, NoInput: true})
	renderer.Out = &out
	renderer.Err = &errOut
	client := proton.New(proton.Options{BaseURL: "http://127.0.0.1:1"})
	client.SetTokens("uid", "access", "refresh")
	a := &app.App{API: client, UI: renderer, DryRun: true}

	cmd := New()
	cmd.SetArgs([]string{"POST", "/core/v4/labels", "--body", `{}`})
	if err := cmd.ExecuteContext(app.WithApp(context.Background(), a)); err != nil {
		t.Fatalf("dry-run raw API request: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty", out.String())
	}
	if got := errOut.String(); !strings.Contains(got, "Dry run") || !strings.Contains(got, "POST /core/v4/labels") {
		t.Errorf("dry-run report = %q", got)
	}
}

func TestDryRunStillSendsReadOnlyRawRequest(t *testing.T) {
	var calls int
	hc := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", req.Method)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    req,
		}, nil
	})}
	client := proton.New(proton.Options{BaseURL: "https://example.test", HTTPClient: hc})
	client.SetTokens("uid", "access", "refresh")
	renderer := ui.New(ui.Options{Format: ui.FormatText, NoInput: true})
	renderer.Out = &bytes.Buffer{}
	renderer.Err = &bytes.Buffer{}
	a := &app.App{API: client, UI: renderer, DryRun: true}

	cmd := New()
	cmd.SetArgs([]string{"get", "/core/v4/users"})
	if err := cmd.ExecuteContext(app.WithApp(context.Background(), a)); err != nil {
		t.Fatalf("dry-run GET: %v", err)
	}
	if calls != 1 {
		t.Errorf("request calls = %d, want 1", calls)
	}
}

func TestNormalMutatingRawRequestStillRuns(t *testing.T) {
	var calls int
	hc := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodPatch {
			t.Errorf("method = %s, want PATCH", req.Method)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Request:    req,
		}, nil
	})}
	client := proton.New(proton.Options{BaseURL: "https://example.test", HTTPClient: hc})
	client.SetTokens("uid", "access", "refresh")
	renderer := ui.New(ui.Options{Format: ui.FormatText, NoInput: true})
	renderer.Out = &bytes.Buffer{}
	renderer.Err = &bytes.Buffer{}
	a := &app.App{API: client, UI: renderer}

	cmd := New()
	cmd.SetArgs([]string{"patch", "/settings", "--body", `{}`})
	if err := cmd.ExecuteContext(app.WithApp(context.Background(), a)); err != nil {
		t.Fatalf("normal PATCH: %v", err)
	}
	if calls != 1 {
		t.Errorf("request calls = %d, want 1", calls)
	}
}
