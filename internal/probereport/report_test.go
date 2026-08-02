package probereport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/valkey-io/valkey-go"
)

func TestValidToken(t *testing.T) {
	valid := []string{"a1b2c3d4", "0123456789abcdef", "0123456789abcdef0123456789abcdef"}
	for _, s := range valid {
		if !ValidToken(s) {
			t.Errorf("ValidToken(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"",
		"a1b2c3d",                           // too short
		"0123456789abcdef0123456789abcdef0", // too long
		"A1B2C3D4",                          // uppercase: the plugin lowercases before storing, so an
		// uppercase token would name a key that cannot exist
		"zzzzzzzz",    // not hex
		"a1b2c3d4 ",   // trailing space
		"probe:obs:x", // the shape an attacker would try
		"../../etc",
	}
	for _, s := range invalid {
		if ValidToken(s) {
			t.Errorf("ValidToken(%q) = true, want false", s)
		}
	}
}

func TestHandlerRejectsBadRequests(t *testing.T) {
	h := &HTTPHandler{Store: &Store{}}

	tests := []struct {
		name     string
		method   string
		target   string
		wantCode int
	}{
		{name: "no token", method: http.MethodGet, target: "/api/report", wantCode: http.StatusBadRequest},
		{name: "malformed token", method: http.MethodGet, target: "/api/report?token=nothex", wantCode: http.StatusBadRequest},
		{
			// Without validation this would name an arbitrary key in a shared
			// store.
			name: "key-injection attempt", method: http.MethodGet,
			target: "/api/report?token=probe%3Aobs%3Aaaaaaaaa", wantCode: http.StatusBadRequest,
		},
		{name: "wrong method", method: http.MethodPost, target: "/api/report?token=a1b2c3d4", wantCode: http.StatusMethodNotAllowed},
		{
			// Valid token but no store configured: distinguishable from a bad
			// request, so a misconfiguration does not look like a client error.
			name: "no store", method: http.MethodGet,
			target: "/api/report?token=a1b2c3d4", wantCode: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}

// storeForTest connects to a real Valkey when PROBE_VALKEY_ADDR is set. The
// whole point of this package is decoding what a DIFFERENT program wrote, so a
// fake store would test this package against its own assumptions — exactly the
// mistake that would let the key contract drift unnoticed.
func storeForTest(t *testing.T) (*Store, valkey.Client) {
	t.Helper()
	addr := os.Getenv("PROBE_VALKEY_ADDR")
	if addr == "" {
		t.Skip("PROBE_VALKEY_ADDR not set; skipping Valkey integration test")
	}
	c, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("connecting to valkey: %v", err)
	}
	t.Cleanup(c.Close)
	return &Store{Client: c}, c
}

func TestGetUnknownTokenIsEmptyNotError(t *testing.T) {
	// A visitor whose resolver never reached us is a legitimate, interesting
	// result — it must not read as a backend failure.
	s, _ := storeForTest(t)
	r, err := s.Get("ffffffffffffffff")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Queries != 0 || len(r.Observations) != 0 || len(r.Resolvers) != 0 {
		t.Errorf("unknown token returned %+v, want an empty report", r)
	}
	if len(r.ErrorReports) != 0 {
		t.Errorf("unknown token returned %d error reports, want none", len(r.ErrorReports))
	}
	// Encoded as [] rather than null, so the page can iterate without a guard.
	b, _ := json.Marshal(r)
	for _, want := range []string{`"observations":[]`, `"resolvers":[]`, `"error_reports":[]`} {
		if !contains(string(b), want) {
			t.Errorf("empty report should encode %s, got %s", want, b)
		}
	}
}

// TestGetReadsErrorReports decodes bytes written in the plugin's format. The two
// programs share no code, so this is the only thing standing between a renamed
// JSON tag and a page that silently shows "no reports" forever — which is also a
// legitimate reading, and therefore the drift with no loud symptom.
func TestGetReadsErrorReports(t *testing.T) {
	s, c := storeForTest(t)
	const visitorToken = "a1b2c3d4"

	ctx := context.Background()
	key := reportsKey(visitorToken)
	if err := c.Do(ctx, c.B().Del().Key(key).Build()).Error(); err != nil {
		t.Fatalf("DEL: %v", err)
	}
	// Written exactly as probe.ReportRecord marshals it.
	const raw = `{"at":"2026-08-02T10:00:00Z","token":"a1b2c3d4","qtype":16,` +
		`"qtype_name":"TXT","qname":"_expiredsig.a1b2c3d4.check.hivre.com.",` +
		`"ede":7,"ede_text":"Signature Expired","reporter_addr":"192.0.2.53",` +
		`"reporter_prefix":"192.0.2.0/24","transport":"udp"}`
	if err := c.Do(ctx, c.B().Rpush().Key(key).Element(raw).Build()).Error(); err != nil {
		t.Fatalf("RPUSH: %v", err)
	}
	t.Cleanup(func() { _ = c.Do(context.Background(), c.B().Del().Key(key).Build()).Error() })

	r, err := s.Get(visitorToken)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(r.ErrorReports) != 1 {
		t.Fatalf("got %d error reports, want 1", len(r.ErrorReports))
	}
	got := r.ErrorReports[0]
	if got.EDE != 7 || got.EDEText != "Signature Expired" {
		t.Errorf("EDE = %d %q, want 7 \"Signature Expired\"", got.EDE, got.EDEText)
	}
	if got.Qname != "_expiredsig.a1b2c3d4.check.hivre.com." {
		t.Errorf("Qname = %q", got.Qname)
	}
	if got.ReporterAddr != "192.0.2.53" || got.ReporterPrefix != "192.0.2.0/24" {
		t.Errorf("reporter = %s/%s", got.ReporterAddr, got.ReporterPrefix)
	}
	if got.At.IsZero() {
		t.Error("At did not decode; a report with no time cannot be ordered or aged")
	}
	// A report can outlive the observations it is about — that is the normal
	// case, not an edge — so it must not be gated on them existing.
	if len(r.Observations) != 0 {
		t.Fatalf("test setup: expected no observations for this token, got %d", len(r.Observations))
	}
}

// TestUnattributedReportsAreNotServed. The plugin keeps reports whose failing
// name carried no token in a shared list. Serving that from a token-addressed
// endpoint would hand any visitor a feed of other people's resolvers and the
// names they failed on.
func TestUnattributedReportsAreNotServed(t *testing.T) {
	s, c := storeForTest(t)
	const visitorToken = "a1b2c3d4"

	ctx := context.Background()
	const shared = "probe:reports:unattributed"
	const raw = `{"at":"2026-08-02T10:00:00Z","qtype":6,"qtype_name":"SOA",` +
		`"qname":"check.hivre.com.","ede":10,"reporter_addr":"198.51.100.7",` +
		`"reporter_prefix":"198.51.100.0/24","transport":"udp"}`
	if err := c.Do(ctx, c.B().Rpush().Key(shared).Element(raw).Build()).Error(); err != nil {
		t.Fatalf("RPUSH: %v", err)
	}
	t.Cleanup(func() { _ = c.Do(context.Background(), c.B().Del().Key(shared).Build()).Error() })

	r, err := s.Get(visitorToken)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, er := range r.ErrorReports {
		if er.ReporterAddr == "198.51.100.7" {
			t.Fatal("an unattributed report leaked into a token's report")
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
