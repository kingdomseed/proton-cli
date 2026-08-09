package calendar

import (
	"context"
	"crypto/sha1" //nolint:gosec // matching Proton's attendee-token algorithm
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/roman-16/proton-cli/internal/account/keys"
	"github.com/roman-16/proton-cli/internal/errs"
	"github.com/roman-16/proton-cli/internal/proton"
)

func TestAttendeeTokenMatchesSHA1OfUIDAndCanonicalEmail(t *testing.T) {
	// Casing/whitespace are canonicalised away, so these inputs hash identically.
	got := attendeeToken("event-uid-42", "  Alice@Proton.me ")

	sum := sha1.Sum([]byte("event-uid-42" + "alice@proton.me")) //nolint:gosec
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Errorf("attendeeToken = %q, want %q", got, want)
	}
	if len(got) != 40 {
		t.Errorf("expected a 40-char hex SHA-1, got %d chars", len(got))
	}
}

func TestICalTriggerConvertsDurationsToNegativeTriggers(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"15m", "-PT15M"},
		{"1h", "-PT60M"},
		{"90m", "-PT90M"},
		{"1d", "-P1D"},
		{"2d", "-P2D"},
	}
	for _, c := range cases {
		got, err := icalTrigger(c.in)
		if err != nil {
			t.Errorf("icalTrigger(%q) returned error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("icalTrigger(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := icalTrigger("0m"); err == nil {
		t.Error("expected an error for a zero-length reminder")
	}
	if _, err := icalTrigger("not-a-duration"); err == nil {
		t.Error("expected an error for an unparseable reminder")
	}
}

func TestBuildRemindersMapsToDeviceNotifications(t *testing.T) {
	out, err := buildReminders([]string{"15m", "1d"})
	if err != nil {
		t.Fatalf("buildReminders error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(out))
	}
	if out[0]["Type"] != 1 || out[0]["Trigger"] != "-PT15M" {
		t.Errorf("first reminder = %v, want Type 1 / -PT15M", out[0])
	}
	if out[1]["Trigger"] != "-P1D" {
		t.Errorf("second reminder trigger = %v, want -P1D", out[1]["Trigger"])
	}

	if out, _ := buildReminders(nil); out != nil {
		t.Errorf("expected nil for no reminders, got %v", out)
	}
}

func TestDecryptEventCardRejectsInvalidKeyPacket(t *testing.T) {
	_, _, _, _, _, _, err := decryptEventCard(nil, "not base64", nil, nil)
	if err == nil {
		t.Fatal("decryptEventCard accepted an invalid key packet")
	}
}

// ── RSVP: pure seams ──

func TestStatusFromFlag(t *testing.T) {
	cases := map[string]int{"accept": partstatAccepted, "tentative": partstatTentative, "decline": partstatDeclined}
	for in, want := range cases {
		got, err := StatusFromFlag(in)
		if err != nil || got != want {
			t.Errorf("StatusFromFlag(%q) = %d,%v; want %d,nil", in, got, err, want)
		}
	}
	if _, err := StatusFromFlag("maybe"); err == nil {
		t.Error("StatusFromFlag(\"maybe\") should error")
	}
}

func TestPartstatICS(t *testing.T) {
	cases := map[int]string{
		partstatAccepted:    "ACCEPTED",
		partstatTentative:   "TENTATIVE",
		partstatDeclined:    "DECLINED",
		partstatNeedsAction: "NEEDS-ACTION",
	}
	for status, want := range cases {
		if got := partstatICS(status); got != want {
			t.Errorf("partstatICS(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestReplyBodyMatchesWebClientsWording(t *testing.T) {
	cases := map[int]string{
		partstatAccepted:  "me@proton.me accepted your invitation to Sync",
		partstatTentative: "me@proton.me tentatively accepted your invitation to Sync",
		partstatDeclined:  "me@proton.me declined your invitation to Sync",
	}
	for status, want := range cases {
		if got := replyBody("me@proton.me", status, "Sync"); got != want {
			t.Errorf("replyBody(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestFindSelfAttendee(t *testing.T) {
	uid := "uid-9"
	mine := attendeeToken(uid, "me@proton.me")
	attendees := []rawAttendee{{ID: "other", Token: "deadbeef"}, {ID: "mine", Token: mine, Status: 0}}

	t.Run("matches my token", func(t *testing.T) {
		id, email, ok := findSelfAttendee(uid, []keys.Address{{Email: "me@proton.me"}}, attendees)
		if !ok || id != "mine" || email != "me@proton.me" {
			t.Errorf("got (%q,%q,%v), want (mine,me@proton.me,true)", id, email, ok)
		}
	})
	t.Run("canonicalizes case", func(t *testing.T) {
		if _, _, ok := findSelfAttendee(uid, []keys.Address{{Email: "ME@Proton.ME"}}, attendees); !ok {
			t.Error("expected a case-insensitive token match")
		}
	})
	t.Run("no match", func(t *testing.T) {
		if _, _, ok := findSelfAttendee(uid, []keys.Address{{Email: "someone@else.com"}}, attendees); ok {
			t.Error("expected no match for an unrelated address")
		}
	})
}

// ── RSVP: EventRespond wiring (router fake Doer) ──

// routeDoer routes requests by a handler and records every request, so tests
// can assert the exact partstat PUT without a live API or PGP fixtures.
type routeDoer struct {
	reqs    []proton.Request
	handler func(proton.Request) ([]byte, error)
}

func (d *routeDoer) Do(_ context.Context, r proton.Request) (*proton.Response, error) {
	d.reqs = append(d.reqs, r)
	body, err := d.handler(r)
	if err != nil {
		return nil, err
	}
	return &proton.Response{Status: 200, Body: body}, nil
}

func (d *routeDoer) Decode(_ context.Context, r proton.Request, out any) error {
	d.reqs = append(d.reqs, r)
	body, err := d.handler(r)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (d *routeDoer) putTo(substr string) (proton.Request, bool) {
	for _, r := range d.reqs {
		if r.Method == "PUT" && strings.Contains(r.Path, substr) {
			return r, true
		}
	}
	return proton.Request{}, false
}

// eventJSON builds a canned single-event GET body with one attendee.
func eventJSON(t *testing.T, uid string, isOrganizer int, attendees []map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"Event": map[string]any{
		"ID": "ev1", "CalendarID": "cal1", "UID": uid,
		"IsOrganizer": isOrganizer, "IsProtonProtonInvite": 0,
		"StartTime": 1000, "EndTime": 2000, "FullDay": 0,
		"AttendeesInfo": map[string]any{"Attendees": attendees, "MoreAttendees": 0},
		"SharedEvents":  []any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEventRespondUpdatesPartstat(t *testing.T) {
	uid := "uid-1"
	event := eventJSON(t, uid, 0, []map[string]any{{"ID": "att1", "Token": attendeeToken(uid, "me@proton.me"), "Status": 0}})
	d := &routeDoer{handler: func(r proton.Request) ([]byte, error) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.Path, "/events/ev1"):
			return event, nil
		case r.Method == "PUT" && strings.Contains(r.Path, "/attendees/att1"):
			return []byte(`{"Code":1000}`), nil
		default:
			// Members lookup etc.: empty so the best-effort reply build bails.
			return []byte(`{}`), nil
		}
	}}
	u := &keys.Unlocked{Addresses: []keys.Address{{ID: "a1", Email: "me@proton.me"}}}

	res, err := New(d).EventRespond(context.Background(), u, "cal1", "ev1", partstatAccepted)
	if err != nil {
		t.Fatalf("EventRespond: %v", err)
	}
	if res.Status != "accepted" {
		t.Errorf("Status = %q, want accepted", res.Status)
	}
	put, ok := d.putTo("/calendar/v1/cal1/events/ev1/attendees/att1")
	if !ok {
		t.Fatalf("expected a PUT to the attendee endpoint; got %d requests", len(d.reqs))
	}
	body, ok := put.Body.(map[string]any)
	if !ok {
		t.Fatalf("PUT body is not map[string]any: %T", put.Body)
	}
	if body["Status"] != partstatAccepted {
		t.Errorf("PUT Status = %v, want %d", body["Status"], partstatAccepted)
	}
	if ut, _ := body["UpdateTime"].(int64); ut <= 0 {
		t.Errorf("PUT UpdateTime = %v, want a positive unix time", body["UpdateTime"])
	}
}

func TestEventRespondRejectsOrganizer(t *testing.T) {
	event := eventJSON(t, "uid-1", 1, nil)
	d := &routeDoer{handler: func(r proton.Request) ([]byte, error) { return event, nil }}
	u := &keys.Unlocked{Addresses: []keys.Address{{Email: "me@proton.me"}}}

	_, err := New(d).EventRespond(context.Background(), u, "cal1", "ev1", partstatAccepted)
	if err == nil {
		t.Fatal("expected an error when responding as the organizer")
	}
	var coder errs.ExitCoder
	if !errors.As(err, &coder) || coder.ExitCode() != 1 {
		t.Errorf("expected exit 1 (user error), got %v", err)
	}
	if _, ok := d.putTo("/attendees/"); ok {
		t.Error("must not update partstat when the caller is the organizer")
	}
}

func TestEventRespondNotAttendee(t *testing.T) {
	uid := "uid-1"
	event := eventJSON(t, uid, 0, []map[string]any{{"ID": "someoneelse", "Token": "deadbeef", "Status": 0}})
	d := &routeDoer{handler: func(r proton.Request) ([]byte, error) { return event, nil }}
	u := &keys.Unlocked{Addresses: []keys.Address{{Email: "me@proton.me"}}}

	_, err := New(d).EventRespond(context.Background(), u, "cal1", "ev1", partstatAccepted)
	var nf *errs.NotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected *errs.NotFound (exit 3), got %v", err)
	}
	if _, ok := d.putTo("/attendees/"); ok {
		t.Error("must not update partstat when the caller is not an attendee")
	}
}
