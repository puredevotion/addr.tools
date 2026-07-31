package probereport

import (
	"encoding/json"
	"testing"
)

// TestECSDisclosureThreeStates is the whole reason ECSDisclosure exists. The
// pair (ecs, ecs_scope) has three meanings and the middle one is the good news;
// a boolean rendering would report the resolvers behaving best as leaking.
func TestECSDisclosureThreeStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  Observation
		want ECSDisclosure
	}{
		{
			name: "no option sent",
			obs:  Observation{ECS: false, ECSScope: 0},
			want: ECSSilent,
		},
		{
			// RFC 7871 §7.1.2 opt-out. Must not read as a disclosure.
			name: "option sent, prefix length zero",
			obs:  Observation{ECS: true, ECSScope: 0},
			want: ECSDeclined,
		},
		{
			name: "disclosed a /24",
			obs:  Observation{ECS: true, ECSScope: 24, ECSPrefix: "198.51.100.0/24"},
			want: ECSDisclosed,
		},
		{
			// A single bit is still a disclosure.
			name: "disclosed a /1",
			obs:  Observation{ECS: true, ECSScope: 1},
			want: ECSDisclosed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.obs.ECSDisclosure(); got != tc.want {
				t.Errorf("ECSDisclosure() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDELEGReadingDistinguishesSilence guards the same class of mistake for the
// DE bit: a query with no OPT record cannot have carried the bit, so it is
// "unknown", not "unaware". Conflating the two would understate DELEG adoption
// by counting every non-EDNS query as a resolver that rejected it.
func TestDELEGReadingDistinguishesSilence(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  Observation
		want DELEGReading
	}{
		{
			name: "no EDNS at all",
			obs:  Observation{EDNS: false, DELEGAware: false},
			want: DELEGUnknown,
		},
		{
			// Defensive: if EDNS is absent the flag cannot legitimately be set,
			// but the reading must not claim awareness on inconsistent input.
			name: "no EDNS but flag somehow set",
			obs:  Observation{EDNS: false, DELEGAware: true},
			want: DELEGUnknown,
		},
		{
			name: "EDNS present, DE clear",
			obs:  Observation{EDNS: true, DELEGAware: false},
			want: DELEGUnaware,
		},
		{
			name: "EDNS present, DE set",
			obs:  Observation{EDNS: true, DELEGAware: true},
			want: DELEGAwareReading,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.obs.DELEGReading(); got != tc.want {
				t.Errorf("DELEGReading() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNewFieldsDecodeFromPluginJSON pins the JSON tags against the shape the
// probe plugin actually writes. This struct is a hand-maintained mirror of the
// plugin's Observation across two repositories, so a tag typo here is silent —
// the field just stays zero and the page reports "silent" or "unaware" forever.
func TestNewFieldsDecodeFromPluginJSON(t *testing.T) {
	// Field names copied from the plugin's struct tags, not retyped from memory.
	raw := []byte(`{
		"token":"deadbeef",
		"edns":true,
		"ecs":true,
		"ecs_scope":56,
		"ecs_family":2,
		"ecs_prefix":"2001:db8:dead:be00::/56",
		"compact_aware":true,
		"deleg_aware":true
	}`)

	var obs Observation
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if obs.ECSScope != 56 {
		t.Errorf("ECSScope = %d, want 56", obs.ECSScope)
	}
	if obs.ECSFamily != 2 {
		t.Errorf("ECSFamily = %d, want 2", obs.ECSFamily)
	}
	if want := "2001:db8:dead:be00::/56"; obs.ECSPrefix != want {
		t.Errorf("ECSPrefix = %q, want %q", obs.ECSPrefix, want)
	}
	if !obs.CompactAware {
		t.Error("CompactAware = false, want true (tag: compact_aware)")
	}
	if !obs.DELEGAware {
		t.Error("DELEGAware = false, want true (tag: deleg_aware)")
	}
	if got := obs.ECSDisclosure(); got != ECSDisclosed {
		t.Errorf("ECSDisclosure() = %q, want %q", got, ECSDisclosed)
	}
	if got := obs.DELEGReading(); got != DELEGAwareReading {
		t.Errorf("DELEGReading() = %q, want %q", got, DELEGAwareReading)
	}
}
