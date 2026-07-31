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

// TestTrustAnchorReadingDistinguishesSilence — RFC 8145 signals are rare, so the
// common case is silence. Rendering that as "does not hold our key" would turn the
// absence of a signal into a negative finding about the resolver.
func TestTrustAnchorReadingDistinguishesSilence(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  Observation
		want TrustAnchorReading
	}{
		{"no tags signalled", Observation{}, TrustAnchorSilent},
		// Defensive: the flag cannot legitimately be set with no tags, and must
		// not be believed if it is.
		{"flag set but no tags", Observation{KnowsZoneKey: true}, TrustAnchorSilent},
		{"tags, ours among them", Observation{KeyTags: []uint16{0x4444}, KnowsZoneKey: true}, TrustAnchorOurs},
		{"tags, none ours", Observation{KeyTags: []uint16{0x0635}}, TrustAnchorOther},
	} {
		if got := tc.obs.TrustAnchorReading(); got != tc.want {
			t.Errorf("%s: TrustAnchorReading() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestEncryptedFromTransport — derived from Transport rather than from TLS being
// non-nil, so it stays correct for a transport that carries no handshake detail.
func TestEncryptedFromTransport(t *testing.T) {
	for transport, want := range map[string]bool{
		"udp": false, "tcp": false, "": false,
		"tls": true, "quic": true, "https": true,
	} {
		if got := (Observation{Transport: transport}).Encrypted(); got != want {
			t.Errorf("transport %q: Encrypted() = %v, want %v", transport, got, want)
		}
	}
	// A TLS transport with no detail block is still encrypted.
	if !(Observation{Transport: "tls"}).Encrypted() {
		t.Error("tls transport with nil TLS block read as cleartext")
	}
}

// TestRFC8145And9539FieldsDecode pins the new JSON tags against what the plugin
// writes. This struct is a hand-maintained mirror across two repositories, so a
// tag typo is silent: the field stays zero and the page reports "silent" or
// "cleartext" forever, which looks like a finding instead of a bug.
func TestRFC8145And9539FieldsDecode(t *testing.T) {
	raw := []byte(`{
		"token":"deadbeef",
		"transport":"tls",
		"key_tags":[17476,1589],
		"knows_zone_key":true,
		"zoneversion_asked":true,
		"tls":{"version":"TLS 1.3","cipher_suite":"TLS_AES_128_GCM_SHA256",
		       "named_group":"X25519","did_resume":true}
	}`)

	var obs Observation
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(obs.KeyTags) != 2 || obs.KeyTags[0] != 17476 {
		t.Errorf("KeyTags = %v, want [17476 1589] (tag: key_tags)", obs.KeyTags)
	}
	if !obs.KnowsZoneKey {
		t.Error("KnowsZoneKey = false (tag: knows_zone_key)")
	}
	if !obs.ZoneVersionAsked {
		t.Error("ZoneVersionAsked = false (tag: zoneversion_asked)")
	}
	if obs.TLS == nil {
		t.Fatal("TLS = nil (tag: tls)")
	}
	if obs.TLS.NamedGroup != "X25519" {
		t.Errorf("TLS.NamedGroup = %q, want X25519", obs.TLS.NamedGroup)
	}
	if !obs.TLS.DidResume {
		t.Error("TLS.DidResume = false (tag: did_resume)")
	}
	if !obs.Encrypted() {
		t.Error("Encrypted() = false for transport tls")
	}
	if got := obs.TrustAnchorReading(); got != TrustAnchorOurs {
		t.Errorf("TrustAnchorReading() = %q, want %q", got, TrustAnchorOurs)
	}
}
