package odoh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func newTestTarget(t *testing.T) *Target {
	t.Helper()
	tgt, err := NewTarget()
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

func newTestClient(t *testing.T, tgt *Target) *Client {
	t.Helper()
	// Deliberately goes through the WIRE form rather than handing the struct over,
	// so the config encoding is exercised on the path a real client takes.
	cfg, err := ParseConfigs(tgt.ConfigsWire())
	if err != nil {
		t.Fatalf("ParseConfigs: %v", err)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestRoundTrip is the baseline: a query and its response survive end to end.
//
// Weak evidence on its own — a symmetric misreading of RFC 9230 passes this — which
// is why the tests below pin each label, AAD and derivation input separately. Those
// are the parts that fail silently against other implementations.
func TestRoundTrip(t *testing.T) {
	tgt := newTestTarget(t)
	client := newTestClient(t, tgt)

	dnsQuery := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01}
	qmsg, pending, err := client.EncryptQuery(dnsQuery, make([]byte, 32))
	if err != nil {
		t.Fatalf("EncryptQuery: %v", err)
	}

	// Through the wire encoding, as a proxy would forward it.
	parsed, err := ParseMessage(qmsg.Marshal())
	if err != nil {
		t.Fatalf("ParseMessage(query): %v", err)
	}

	gotQuery, qc, err := tgt.DecryptQuery(parsed)
	if err != nil {
		t.Fatalf("DecryptQuery: %v", err)
	}
	if !bytes.Equal(gotQuery, dnsQuery) {
		t.Errorf("query = %x, want %x", gotQuery, dnsQuery)
	}

	dnsResponse := []byte{0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01}
	rmsg, err := tgt.EncryptResponse(qc, dnsResponse, make([]byte, 64))
	if err != nil {
		t.Fatalf("EncryptResponse: %v", err)
	}

	rparsed, err := ParseMessage(rmsg.Marshal())
	if err != nil {
		t.Fatalf("ParseMessage(response): %v", err)
	}
	gotResponse, err := client.DecryptResponse(pending, rparsed)
	if err != nil {
		t.Fatalf("DecryptResponse: %v", err)
	}
	if !bytes.Equal(gotResponse, dnsResponse) {
		t.Errorf("response = %x, want %x", gotResponse, dnsResponse)
	}
}

// TestKeyIDIsDeterministicAndConfigBound — the key ID identifies a config, so it
// must be reproducible from the config alone and must change when the config does.
// A key ID that did not change with the key would let a client encrypt to a
// rotated-away key and get an opaque decrypt failure instead of a refetch signal.
func TestKeyIDIsDeterministicAndConfigBound(t *testing.T) {
	tgt := newTestTarget(t)
	cfg := tgt.Config()

	a, err := cfg.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	b, err := cfg.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("KeyID is not deterministic")
	}
	if len(a) != nh {
		t.Errorf("KeyID is %d bytes, want Nh = %d", len(a), nh)
	}
	if !bytes.Equal(a, tgt.KeyID()) {
		t.Error("target's KeyID differs from the one derived from its own config")
	}

	// A different key must give a different ID.
	other := newTestTarget(t)
	if bytes.Equal(tgt.KeyID(), other.KeyID()) {
		t.Error("two targets with different keys share a key ID")
	}

	// So must a different suite field, since the whole config is the input.
	mutated := cfg
	mutated.AEADID = 0x0002
	m, err := mutated.KeyID()
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if bytes.Equal(a, m) {
		t.Error("key ID did not change when the config's AEAD id changed")
	}
}

// TestKeyIDMismatchIsAuthorizationNotCorruption — RFC 9230 §8 makes this an
// authorization failure (HTTP 401). The distinction is operational: a client with a
// stale config must refetch, and reporting it as a decrypt error would have it
// pointlessly retry the same doomed request.
func TestKeyIDMismatchIsAuthorizationNotCorruption(t *testing.T) {
	tgt := newTestTarget(t)
	other := newTestTarget(t)
	client := newTestClient(t, other) // encrypts to the WRONG target

	qmsg, _, err := client.EncryptQuery([]byte{0x00, 0x01}, nil)
	if err != nil {
		t.Fatalf("EncryptQuery: %v", err)
	}
	if _, _, err := tgt.DecryptQuery(qmsg); !errors.Is(err, ErrKeyIDMismatch) {
		t.Errorf("err = %v, want ErrKeyIDMismatch", err)
	}
}

// TestAADBindsKeyIDAndMessageType is the security property behind the AAD. Flipping
// either value must make the ciphertext unopenable — if it did not, a proxy could
// rewrite the message type or retarget a query and the target would accept it.
func TestAADBindsKeyIDAndMessageType(t *testing.T) {
	tgt := newTestTarget(t)
	client := newTestClient(t, tgt)

	qmsg, _, err := client.EncryptQuery([]byte{0x00, 0x01}, nil)
	if err != nil {
		t.Fatalf("EncryptQuery: %v", err)
	}

	t.Run("tampered key id", func(t *testing.T) {
		bad := qmsg
		bad.KeyID = bytes.Clone(qmsg.KeyID)
		bad.KeyID[0] ^= 0xff
		// Caught as a mismatch before decryption even runs, which is the point:
		// the check is cheap and the error is actionable.
		if _, _, err := tgt.DecryptQuery(bad); err == nil {
			t.Error("accepted a tampered key id")
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		bad := qmsg
		bad.Encrypted = bytes.Clone(qmsg.Encrypted)
		bad.Encrypted[len(bad.Encrypted)-1] ^= 0xff
		if _, _, err := tgt.DecryptQuery(bad); err == nil {
			t.Error("accepted a tampered ciphertext")
		}
	})

	t.Run("message type flipped to response", func(t *testing.T) {
		bad := qmsg
		bad.Type = MessageTypeResponse
		if _, _, err := tgt.DecryptQuery(bad); err == nil {
			t.Error("target decrypted a message labelled as a response")
		}
	})
}

// TestResponseIsBoundToItsQuery — RFC 9230 derives the response key from the query
// plaintext, so a response cannot be replayed onto a different query. This is the
// property that stops a proxy swapping answers between concurrent clients.
func TestResponseIsBoundToItsQuery(t *testing.T) {
	tgt := newTestTarget(t)
	client := newTestClient(t, tgt)

	q1, p1, err := client.EncryptQuery([]byte{0x00, 0x01}, nil)
	if err != nil {
		t.Fatal(err)
	}
	q2, p2, err := client.EncryptQuery([]byte{0x00, 0x02}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, qc1, err := tgt.DecryptQuery(q1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tgt.DecryptQuery(q2); err != nil {
		t.Fatal(err)
	}

	r1, err := tgt.EncryptResponse(qc1, []byte{0xaa, 0xbb}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The right pairing works.
	if _, err := client.DecryptResponse(p1, r1); err != nil {
		t.Fatalf("correct pairing failed: %v", err)
	}
	// The wrong one must not.
	if _, err := client.DecryptResponse(p2, r1); err == nil {
		t.Error("a response opened against a different query's context")
	}
}

// TestResponseNonceIsFresh — the nonce feeds the AEAD key derivation, so repeating
// it across responses would reuse an AES-GCM key/nonce pair. Catastrophic and
// entirely silent.
func TestResponseNonceIsFresh(t *testing.T) {
	tgt := newTestTarget(t)
	client := newTestClient(t, tgt)

	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		q, _, err := client.EncryptQuery([]byte{0x00, byte(i)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, qc, err := tgt.DecryptQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		r, err := tgt.EncryptResponse(qc, []byte{0xaa}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.KeyID) != respNonceLen {
			t.Fatalf("response nonce is %d bytes, want %d", len(r.KeyID), respNonceLen)
		}
		if seen[string(r.KeyID)] {
			t.Fatal("response nonce repeated")
		}
		seen[string(r.KeyID)] = true
	}
}

// TestParseMessageRejectsHostileFraming — this parses the body of an
// unauthenticated POST from anyone who can reach the endpoint.
func TestParseMessageRejectsHostileFraming(t *testing.T) {
	valid := Message{Type: MessageTypeQuery, KeyID: bytes.Repeat([]byte{1}, 32), Encrypted: bytes.Repeat([]byte{2}, 64)}.Marshal()

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"type only", []byte{0x01}},
		{"truncated key id length", []byte{0x01, 0x00}},
		{"key id longer than remaining", []byte{0x01, 0xff, 0xff, 0x00}},
		{"missing encrypted length", append([]byte{0x01, 0x00, 0x01}, 0x41)},
		{"encrypted longer than remaining", []byte{0x01, 0x00, 0x00, 0xff, 0xff, 0x41}},
		{"empty encrypted message", []byte{0x01, 0x00, 0x00, 0x00, 0x00}},
		// Trailing bytes after a well-formed message: the framing disagrees with
		// the transport, and guessing which is right is how a parser becomes a
		// smuggling vector.
		{"trailing garbage", append(bytes.Clone(valid), 0xff, 0xff)},
		{"truncated body", valid[:len(valid)-8]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseMessage(tc.in); err == nil {
				t.Error("accepted hostile framing")
			}
		})
	}

	if _, err := ParseMessage(valid); err != nil {
		t.Errorf("rejected a valid message: %v", err)
	}
}

// TestPaddingMustBeZero — RFC 9230 §6.1 requires all-zero padding. Non-zero padding
// is a covert channel through a hop whose entire purpose is obliviousness, so
// accepting it silently would undermine the guarantee the page advertises.
func TestPaddingMustBeZero(t *testing.T) {
	good := Plaintext{DNSMessage: []byte{0xaa, 0xbb}, Padding: make([]byte, 8)}.Marshal()
	if _, err := ParsePlaintext(good); err != nil {
		t.Fatalf("rejected zero padding: %v", err)
	}

	bad := Plaintext{DNSMessage: []byte{0xaa, 0xbb}, Padding: []byte{0, 0, 1, 0}}.Marshal()
	if _, err := ParsePlaintext(bad); err == nil {
		t.Error("accepted non-zero padding, which is a covert channel")
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"empty dns message", []byte{0x00, 0x00, 0x00, 0x00}},
		{"dns length exceeds body", []byte{0xff, 0xff, 0x41}},
		{"padding length mismatch", []byte{0x00, 0x01, 0x41, 0x00, 0x09, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePlaintext(tc.in); err == nil {
				t.Error("accepted malformed plaintext")
			}
		})
	}
}

// TestParseConfigsSkipsUnknownVersions — RFC 9230 §5 requires it, and it is what
// keeps this target working when a client offers a newer config alongside one we
// understand. Failing instead would break interop on the day someone deploys v2.
func TestParseConfigsSkipsUnknownVersions(t *testing.T) {
	tgt := newTestTarget(t)
	known := tgt.Config().MarshalConfig()

	// A plausible future config: unknown version, arbitrary body.
	future := []byte{}
	future = binary.BigEndian.AppendUint16(future, 0x0002)
	body := bytes.Repeat([]byte{0xcc}, 12)
	future = binary.BigEndian.AppendUint16(future, wireLen(len(body)))
	future = append(future, body...)

	t.Run("unknown first", func(t *testing.T) {
		inner := append(bytes.Clone(future), known...)
		var wire []byte
		wire = binary.BigEndian.AppendUint16(wire, wireLen(len(inner)))
		wire = append(wire, inner...)

		cfg, err := ParseConfigs(wire)
		if err != nil {
			t.Fatalf("ParseConfigs: %v", err)
		}
		if !bytes.Equal(cfg.PublicKey, tgt.Config().PublicKey) {
			t.Error("did not select the supported config")
		}
	})

	t.Run("only unknown versions", func(t *testing.T) {
		var wire []byte
		wire = binary.BigEndian.AppendUint16(wire, wireLen(len(future)))
		wire = append(wire, future...)
		if _, err := ParseConfigs(wire); !errors.Is(err, ErrUnsupportedSuite) {
			t.Errorf("err = %v, want ErrUnsupportedSuite", err)
		}
	})

	t.Run("hostile framing", func(t *testing.T) {
		for _, in := range [][]byte{
			nil, {0x00}, {0x00, 0x05}, {0x00, 0x02, 0x00},
			{0x00, 0x04, 0x00, 0x01, 0xff, 0xff},
		} {
			if _, err := ParseConfigs(in); err == nil {
				t.Errorf("%x accepted", in)
			}
		}
	})
}

// TestClientRejectsUnsupportedSuite — better to refuse at setup than to build
// ciphertext no target can open.
func TestClientRejectsUnsupportedSuite(t *testing.T) {
	base := newTestTarget(t).Config()

	for _, tc := range []struct {
		name string
		mut  func(c *ConfigContents)
	}{
		{"kem", func(c *ConfigContents) { c.KEMID = 0x0010 }},
		{"kdf", func(c *ConfigContents) { c.KDFID = 0x0003 }},
		{"aead", func(c *ConfigContents) { c.AEADID = 0x0003 }},
		{"no public key", func(c *ConfigContents) { c.PublicKey = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			if _, err := NewClient(cfg); err == nil {
				t.Error("accepted an unusable config")
			}
		})
	}
}
