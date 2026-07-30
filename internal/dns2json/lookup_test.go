package dns2json

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLookupAllowlist guards the property that keeps this endpoint from being an
// open resolver reachable over HTTP — which would make it a reconnaissance proxy
// and an amplification reflector using our own address and reputation.
func TestLookupAllowlist(t *testing.T) {
	h := &LookupHandler{
		// No Upstream set: every case here is decided before any DNS query is
		// made, which is the point.
		AllowedZones: []string{"check.hivre.com", "hivre.com."},
	}

	tests := []struct {
		name  string
		qname string
		allow bool
	}{
		{name: "exact zone", qname: "hivre.com", allow: true},
		{name: "below zone", qname: "a1b2c3d4.check.hivre.com", allow: true},
		{name: "trailing dot", qname: "check.hivre.com.", allow: true},
		{name: "case insensitive", qname: "A1B2C3D4.Check.Hivre.Com", allow: true},

		{name: "unrelated name", qname: "example.com", allow: false},
		{name: "someone else's host", qname: "login.bank.example", allow: false},
		// The classic bypass: a name that merely ends with the zone's text.
		{name: "suffix lookalike", qname: "nothivre.com", allow: false},
		{name: "parent of the zone", qname: "com", allow: false},
		{name: "root", qname: ".", allow: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.allows(tc.qname); got != tc.allow {
				t.Errorf("allows(%q) = %v, want %v", tc.qname, got, tc.allow)
			}
		})
	}
}

func TestLookupRejectsDisallowedNameWithForbidden(t *testing.T) {
	h := &LookupHandler{AllowedZones: []string{"hivre.com"}}
	req := httptest.NewRequest(http.MethodGet, "/dns/example.com/A", nil)
	req.SetPathValue("name", "example.com")
	req.SetPathValue("type", "A")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestEmptyAllowlistFailsClosed: if the handler is ever constructed without
// zones, it must answer nothing rather than everything. Config refuses to
// register it in that state, so this is the second line of defence.
func TestEmptyAllowlistFailsClosed(t *testing.T) {
	h := &LookupHandler{}
	for _, n := range []string{"hivre.com", "example.com", "."} {
		if h.allows(n) {
			t.Errorf("empty allowlist permitted %q", n)
		}
	}
}
