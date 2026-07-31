package probereport

import "testing"

func obs(mods, qtype string) Observation {
	return Observation{Token: "deadbeef", Mods: mods, Qtype: qtype}
}

// TestQNAMEMinimisation covers the three readings, and the reason the third is
// "unknown" rather than "absent" is the point of the whole file: reporting an
// unprovable absence as a finding would penalise resolvers that minimise in the
// relaxed (A-query) style, which is indistinguishable from the page's own queries.
func TestQNAMEMinimisation(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  []Observation
		want QNAMEMinimisation
	}{
		{
			// The reliable signal: NS on the bare token, which the page never asks
			// for, alongside a modified name it did.
			name: "NS on the intermediate name",
			obs:  []Observation{obs("none", "NS"), obs("badsig", "TXT")},
			want: QMinObserved,
		},
		{
			// Order must not matter: the walk and the real query can be recorded in
			// either order under a shared store.
			name: "NS recorded after the real query",
			obs:  []Observation{obs("badsig", "TXT"), obs("none", "NS")},
			want: QMinObserved,
		},
		{
			name: "modified names asked directly, no intermediate NS",
			obs:  []Observation{obs("badsig", "TXT"), obs("expiredsig", "TXT")},
			want: QMinAbsent,
		},
		{
			// The ambiguous case. An A query on the bare token is exactly what the
			// page itself sends, so it is NOT evidence of relaxed minimisation and
			// must not be read as evidence against it either.
			name: "only bare-token A queries",
			obs:  []Observation{obs("none", "A"), obs("none", "AAAA"), obs("none", "TXT")},
			want: QMinUnknown,
		},
		{
			name: "no observations at all",
			obs:  nil,
			want: QMinUnknown,
		},
		{
			// A bare-token A query plus a modified name: the resolver had the
			// opportunity and left no NS trace.
			name: "bare A plus modified, still absent",
			obs:  []Observation{obs("none", "A"), obs("badsig", "TXT")},
			want: QMinAbsent,
		},
		{
			// Mods empty rather than the literal "none" must behave the same; the
			// plugin writes "none" but an older record may not.
			name: "empty mods treated as unmodified",
			obs:  []Observation{obs("", "NS"), obs("badsig", "TXT")},
			want: QMinObserved,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Token: "deadbeef", Observations: tc.obs}
			if got := r.QNAMEMinimisation(); got != tc.want {
				t.Errorf("QNAMEMinimisation() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestQNAMEMinimisationPositiveEvidenceWins — a resolver that minimised has
// minimised, regardless of what else it did afterwards (retries, a second egress
// address, duplicate queries).
func TestQNAMEMinimisationPositiveEvidenceWins(t *testing.T) {
	r := &Report{Observations: []Observation{
		obs("none", "NS"),
		obs("badsig", "TXT"),
		obs("badsig", "TXT"), // duplicate
		obs("none", "A"),     // page's own query
		obs("expiredsig", "TXT"),
	}}
	if got := r.QNAMEMinimisation(); got != QMinObserved {
		t.Errorf("QNAMEMinimisation() = %q, want %q", got, QMinObserved)
	}
}
