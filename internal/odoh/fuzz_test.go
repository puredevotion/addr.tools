package odoh

import (
	"encoding/binary"
	"testing"
)

// Fuzz targets for the three parsers that read bytes chosen by whoever is
// talking to us.
//
// This is not defensive box-ticking: an ObliviousDoHMessage is the body of an
// UNAUTHENTICATED HTTP POST, and the whole point of an oblivious target is that
// it cannot know who sent it. There is no rate-limiting identity to fall back on
// and no client to blame, so the parsers have to be correct against arbitrary
// input rather than merely against well-formed input.
//
// Each target asserts the same two properties, which are the only ones a parser
// can honestly promise: it must not panic, and anything it accepts must
// round-trip to the same bytes. The second matters more than it looks — a parser
// that accepts input it cannot reproduce is one that disagrees with the sender
// about what was said, which for a length-prefixed format means a framing
// confusion an attacker chooses.

func FuzzParseMessage(f *testing.F) {
	// Seeds: a well-formed message, plus the shapes most likely to break framing.
	valid := Message{
		Type:      MessageTypeQuery,
		KeyID:     make([]byte, 32),
		Encrypted: make([]byte, 48),
	}.Marshal()
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x02, 0xff, 0xff, 0x41})
	f.Add(append(valid, 0xff))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseMessage(data)
		if err != nil {
			return
		}
		// Accepted input must re-encode to exactly what came in. If it does not,
		// the parser tolerated framing it cannot represent.
		if got := msg.Marshal(); string(got) != string(data) {
			t.Fatalf("round trip changed the bytes:\n in: %x\nout: %x", data, got)
		}
	})
}

func FuzzParseConfigs(f *testing.F) {
	valid := ConfigContents{
		KEMID:     KEMX25519HKDFSHA256,
		KDFID:     KDFHKDFSHA256,
		AEADID:    AEADAES128GCM,
		PublicKey: make([]byte, 32),
	}.MarshalConfigs()
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x04, 0x00, 0x01, 0xff, 0xff})

	// A config list whose only entry is an unknown version: must be skipped, not
	// mistaken for a supported one.
	var future []byte
	future = binary.BigEndian.AppendUint16(future, 0x0002)
	future = binary.BigEndian.AppendUint16(future, 4)
	future = append(future, 0xde, 0xad, 0xbe, 0xef)
	var wrapped []byte
	wrapped = binary.BigEndian.AppendUint16(wrapped, wireLen(len(future)))
	f.Add(append(wrapped, future...))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfigs(data)
		if err != nil {
			return
		}
		// Anything accepted must be a suite we can actually use, or the caller
		// will build ciphertext no target can open.
		if cfg.KEMID != KEMX25519HKDFSHA256 || cfg.KDFID != KDFHKDFSHA256 || cfg.AEADID != AEADAES128GCM {
			t.Fatalf("accepted an unsupported suite: kem=%#04x kdf=%#04x aead=%#04x",
				cfg.KEMID, cfg.KDFID, cfg.AEADID)
		}
		if len(cfg.PublicKey) == 0 {
			t.Fatal("accepted a config with no public key")
		}
		// A key ID must be derivable from anything we accepted; failing here
		// would mean the config is usable for encryption but not identifiable.
		if _, err := cfg.KeyID(); err != nil {
			t.Fatalf("accepted a config whose key id cannot be derived: %v", err)
		}
	})
}

func FuzzParsePlaintext(f *testing.F) {
	f.Add(Plaintext{DNSMessage: []byte{0xaa, 0xbb}, Padding: make([]byte, 8)}.Marshal())
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0x41})
	// Non-zero padding: must be rejected, since it is a covert channel through a
	// hop whose entire purpose is obliviousness.
	f.Add([]byte{0x00, 0x01, 0x41, 0x00, 0x02, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePlaintext(data)
		if err != nil {
			return
		}
		if len(p.DNSMessage) == 0 {
			t.Fatal("accepted an empty dns_message")
		}
		for i, c := range p.Padding {
			if c != 0 {
				t.Fatalf("accepted non-zero padding at %d: %#02x", i, c)
			}
		}
		if got := (Plaintext{DNSMessage: p.DNSMessage, Padding: p.Padding}).Marshal(); string(got) != string(data) {
			t.Fatalf("round trip changed the bytes:\n in: %x\nout: %x", data, got)
		}
	})
}
