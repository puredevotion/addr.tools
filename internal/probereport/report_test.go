package probereport

import (
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
	// Encoded as [] rather than null, so the page can iterate without a guard.
	b, _ := json.Marshal(r)
	if !contains(string(b), `"observations":[]`) || !contains(string(b), `"resolvers":[]`) {
		t.Errorf("empty report should encode empty arrays, got %s", b)
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
