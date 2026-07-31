// Package odoh implements the Oblivious DoH target role from RFC 9230.
//
// # What this buys the lab
//
// Every other measurement here tells a visitor what their resolver disclosed. This
// one demonstrates the opposite by construction: a query that arrives obliviously
// reaches us with the visitor's resolver address genuinely unknown to us, because
// an intermediary forwarded it and only the intermediary saw the source. Set beside
// the ECS panel ("your resolver disclosed your /24"), it is the only measurement in
// the lab where the good outcome is *us knowing less*.
//
// # Status of the specification, corrected
//
// RFC 9230, published June 2022 — NOT a stalled draft. The IETF-track
// draft-pauly-dprive-oblivious-doh did stall, and the work was published on the
// **Independent Submission stream** instead. That stream is explicitly *not
// endorsed by the IETF*, and the RFC is Experimental. So it is a real, stable,
// citable specification with real deployments (Cloudflare runs a target), but it is
// not an IETF consensus document, and nothing here should imply otherwise.
//
// # Dependencies
//
// None added. Go 1.26 has crypto/hpke (RFC 9180) and crypto/hkdf in the standard
// library, which is what makes this tractable at all — the earlier estimate that
// this needed a third-party HPKE was wrong.
//
// # Scope
//
// The cryptographic and wire core: config encoding, key ID derivation, message
// framing, query decryption and response encryption. The HTTP endpoint and the
// forward-to-resolver step are deliberately separate, for the same reason the RFC
// 9567 parser landed before its handler: this is the part with a security boundary
// and it is fully testable in isolation.
package odoh

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Suite identifiers from RFC 9180's registries. Only the mandatory-to-implement
// combination is supported: a measurement target has no reason to offer choice,
// and every extra suite is another path to get wrong.
const (
	KEMX25519HKDFSHA256 uint16 = 0x0020
	KDFHKDFSHA256       uint16 = 0x0001
	AEADAES128GCM       uint16 = 0x0001

	// ConfigVersion is RFC 9230 §5's only defined codepoint.
	ConfigVersion uint16 = 0x0001

	// nh is the KDF's output length (SHA-256), used for the key ID.
	nh = 32
	// nk and nn are the AEAD key and nonce lengths for AES-128-GCM.
	nk = 16
	nn = 12

	// respNonceLen is max(Nn, Nk) per RFC 9230 §8, so the same nonce is usable
	// whichever of the two is longer.
	respNonceLen = 16
)

// Message types from RFC 9230 §6.1.
const (
	MessageTypeQuery    byte = 0x01
	MessageTypeResponse byte = 0x02
)

var (
	// ErrUnsupportedSuite means the config named a ciphersuite this target does
	// not implement. Distinguished from malformed input because it is an
	// interoperability fact rather than an attack.
	ErrUnsupportedSuite = errors.New("odoh: unsupported HPKE ciphersuite")
	// ErrKeyIDMismatch means the client encrypted to a key this target does not
	// hold. RFC 9230 §8 makes this an authorization failure (HTTP 401), NOT a
	// decryption error — the distinction matters because a client that has a stale
	// config needs to refetch it, not retry.
	ErrKeyIDMismatch = errors.New("odoh: key id does not match this target's config")
	// ErrMalformed means the wire encoding did not parse.
	ErrMalformed = errors.New("odoh: malformed message")
)

// ConfigContents is RFC 9230 §5's ObliviousDoHConfigContents.
type ConfigContents struct {
	KEMID     uint16
	KDFID     uint16
	AEADID    uint16
	PublicKey []byte
}

// Marshal encodes ConfigContents. This exact byte string is the input to the key
// ID derivation, so its encoding is part of the protocol rather than an internal
// detail — a client and target that encode it differently derive different key IDs
// and fail to interoperate for no visible reason.
func (c ConfigContents) Marshal() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, c.KEMID)
	b = binary.BigEndian.AppendUint16(b, c.KDFID)
	b = binary.BigEndian.AppendUint16(b, c.AEADID)
	b = binary.BigEndian.AppendUint16(b, uint16(len(c.PublicKey)))
	return append(b, c.PublicKey...)
}

// KeyID derives the identifier RFC 9230 §6.1 specifies:
//
//	Expand(Extract("", config), "odoh key id", Nh)
//
// Note the Extract salt is EMPTY and the config bytes are the *secret*, which is
// backwards from how HKDF is usually called and easy to transpose. Transposing it
// yields a stable, plausible-looking identifier that no other implementation
// agrees with.
func (c ConfigContents) KeyID() ([]byte, error) {
	if c.KDFID != KDFHKDFSHA256 {
		return nil, fmt.Errorf("%w: kdf %#04x", ErrUnsupportedSuite, c.KDFID)
	}
	// Extract(salt="", secret=config): Go takes (secret, salt), so the config
	// bytes are the SECRET and the salt is empty. Reversing these produces a
	// stable, plausible key ID that no other implementation agrees with.
	prk, err := hkdf.Extract(sha256.New, c.Marshal(), nil)
	if err != nil {
		return nil, fmt.Errorf("odoh: extracting key id prk: %w", err)
	}
	return hkdf.Expand(sha256.New, prk, "odoh key id", nh)
}

// Marshal encodes a full ObliviousDoHConfig (version + length + contents).
func (c ConfigContents) MarshalConfig() []byte {
	contents := c.Marshal()
	var b []byte
	b = binary.BigEndian.AppendUint16(b, ConfigVersion)
	b = binary.BigEndian.AppendUint16(b, uint16(len(contents)))
	return append(b, contents...)
}

// MarshalConfigs encodes an ObliviousDoHConfigs list holding this one config —
// the form published to clients.
func (c ConfigContents) MarshalConfigs() []byte {
	cfg := c.MarshalConfig()
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(cfg)))
	return append(b, cfg...)
}

// ParseConfigs decodes an ObliviousDoHConfigs list and returns the first config
// with a version and suite this implementation supports.
//
// RFC 9230 §5 requires unknown versions to be SKIPPED rather than treated as
// errors, which is what makes the format forward-compatible. Failing on them would
// break this target the moment a client offers a newer config alongside one we
// understand.
func ParseConfigs(b []byte) (ConfigContents, error) {
	if len(b) < 2 {
		return ConfigContents{}, fmt.Errorf("%w: configs shorter than length prefix", ErrMalformed)
	}
	total := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if total != len(b) {
		return ConfigContents{}, fmt.Errorf("%w: configs length %d but %d bytes follow", ErrMalformed, total, len(b))
	}

	for len(b) > 0 {
		if len(b) < 4 {
			return ConfigContents{}, fmt.Errorf("%w: truncated config header", ErrMalformed)
		}
		version := binary.BigEndian.Uint16(b[0:2])
		length := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if length > len(b) {
			return ConfigContents{}, fmt.Errorf("%w: config length exceeds available bytes", ErrMalformed)
		}
		body := b[:length]
		b = b[length:]

		if version != ConfigVersion {
			continue // forward compatibility, per §5
		}
		c, err := parseConfigContents(body)
		if err != nil {
			return ConfigContents{}, err
		}
		if c.KEMID != KEMX25519HKDFSHA256 || c.KDFID != KDFHKDFSHA256 || c.AEADID != AEADAES128GCM {
			continue // known version, unsupported suite: keep looking
		}
		return c, nil
	}
	return ConfigContents{}, ErrUnsupportedSuite
}

func parseConfigContents(b []byte) (ConfigContents, error) {
	if len(b) < 8 {
		return ConfigContents{}, fmt.Errorf("%w: truncated config contents", ErrMalformed)
	}
	c := ConfigContents{
		KEMID:  binary.BigEndian.Uint16(b[0:2]),
		KDFID:  binary.BigEndian.Uint16(b[2:4]),
		AEADID: binary.BigEndian.Uint16(b[4:6]),
	}
	klen := int(binary.BigEndian.Uint16(b[6:8]))
	b = b[8:]
	if klen == 0 {
		// The spec's public_key field is <1..2^16-1>: empty is malformed, and
		// accepting it would mean deriving a key ID for a config nobody can use.
		return ConfigContents{}, fmt.Errorf("%w: empty public key", ErrMalformed)
	}
	if klen > len(b) {
		return ConfigContents{}, fmt.Errorf("%w: public key length exceeds available bytes", ErrMalformed)
	}
	c.PublicKey = b[:klen]
	return c, nil
}

// Message is RFC 9230 §6.1's ObliviousDoHMessage.
type Message struct {
	Type      byte
	KeyID     []byte
	Encrypted []byte
}

// Marshal encodes a Message.
func (m Message) Marshal() []byte {
	b := []byte{m.Type}
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.KeyID)))
	b = append(b, m.KeyID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Encrypted)))
	return append(b, m.Encrypted...)
}

// ParseMessage decodes a Message.
//
// Every length here is attacker-chosen: this parses the body of an unauthenticated
// HTTP POST from anyone who can reach the endpoint. Each bound is checked against
// what actually remains rather than against the claimed total.
func ParseMessage(b []byte) (Message, error) {
	var m Message
	if len(b) < 1 {
		return m, fmt.Errorf("%w: empty", ErrMalformed)
	}
	m.Type = b[0]
	b = b[1:]

	if len(b) < 2 {
		return m, fmt.Errorf("%w: truncated key_id length", ErrMalformed)
	}
	klen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if klen > len(b) {
		return m, fmt.Errorf("%w: key_id length exceeds available bytes", ErrMalformed)
	}
	m.KeyID = b[:klen]
	b = b[klen:]

	if len(b) < 2 {
		return m, fmt.Errorf("%w: truncated encrypted_message length", ErrMalformed)
	}
	elen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if elen != len(b) {
		// Exact, not "at most": trailing bytes after a well-formed message mean
		// the framing disagrees with the transport, and guessing which is right is
		// how a parser becomes a smuggling vector.
		return m, fmt.Errorf("%w: encrypted_message length %d but %d bytes follow", ErrMalformed, elen, len(b))
	}
	if elen == 0 {
		return m, fmt.Errorf("%w: empty encrypted_message", ErrMalformed)
	}
	m.Encrypted = b
	return m, nil
}

// Plaintext is RFC 9230 §6.1's ObliviousDoHMessagePlaintext.
type Plaintext struct {
	DNSMessage []byte
	Padding    []byte
}

// Marshal encodes a Plaintext.
func (p Plaintext) Marshal() []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.DNSMessage)))
	b = append(b, p.DNSMessage...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.Padding)))
	return append(b, p.Padding...)
}

// ParsePlaintext decodes a Plaintext and verifies the padding is all zeros.
//
// RFC 9230 §6.1 says padding MUST be all zeros. Checking it matters more than it
// looks: non-zero padding is a covert channel through an "oblivious" hop, which is
// precisely the property this protocol exists to provide. Accepting it silently
// would undermine the guarantee the page is about to advertise.
func ParsePlaintext(b []byte) (Plaintext, error) {
	var p Plaintext
	if len(b) < 2 {
		return p, fmt.Errorf("%w: truncated dns_message length", ErrMalformed)
	}
	dlen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if dlen == 0 {
		return p, fmt.Errorf("%w: empty dns_message", ErrMalformed)
	}
	if dlen > len(b) {
		return p, fmt.Errorf("%w: dns_message length exceeds available bytes", ErrMalformed)
	}
	p.DNSMessage = b[:dlen]
	b = b[dlen:]

	if len(b) < 2 {
		return p, fmt.Errorf("%w: truncated padding length", ErrMalformed)
	}
	plen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if plen != len(b) {
		return p, fmt.Errorf("%w: padding length %d but %d bytes follow", ErrMalformed, plen, len(b))
	}
	for _, c := range b {
		if c != 0 {
			return p, fmt.Errorf("%w: padding is not all zeros", ErrMalformed)
		}
	}
	p.Padding = b
	return p, nil
}

// Target holds a key pair and answers oblivious queries.
type Target struct {
	priv     *ecdh.PrivateKey
	hpkePriv hpke.PrivateKey
	contents ConfigContents
	keyID    []byte
}

// NewTarget generates a fresh X25519 key pair.
//
// Fresh per process, deliberately. An ODoH key is not an identity and has no
// reason to persist: rotating it on restart bounds how long any recorded
// ciphertext stays decryptable, and clients refetch the config anyway. The cost is
// that a client holding a stale config gets ErrKeyIDMismatch and must refetch,
// which RFC 9230 §8 already defines a response for.
func NewTarget() (*Target, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("odoh: generating X25519 key: %w", err)
	}
	return newTargetFromKey(priv)
}

func newTargetFromKey(priv *ecdh.PrivateKey) (*Target, error) {
	hp, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("odoh: wrapping key for HPKE: %w", err)
	}
	contents := ConfigContents{
		KEMID:     KEMX25519HKDFSHA256,
		KDFID:     KDFHKDFSHA256,
		AEADID:    AEADAES128GCM,
		PublicKey: priv.PublicKey().Bytes(),
	}
	keyID, err := contents.KeyID()
	if err != nil {
		return nil, err
	}
	return &Target{priv: priv, hpkePriv: hp, contents: contents, keyID: keyID}, nil
}

// Config returns the contents a client needs.
func (t *Target) Config() ConfigContents { return t.contents }

// KeyID returns this target's key identifier.
func (t *Target) KeyID() []byte { return t.keyID }

// ConfigsWire returns the published ObliviousDoHConfigs bytes.
func (t *Target) ConfigsWire() []byte { return t.contents.MarshalConfigs() }

// QueryContext carries the state needed to answer one query. The HPKE context is
// per-query and must not be reused: the response key derivation exports from it,
// and RFC 9230 binds that export to this query's plaintext.
type QueryContext struct {
	recipient  *hpke.Recipient
	queryPlain []byte
}

// DecryptQuery decrypts an oblivious query and returns the DNS message plus the
// context needed to encrypt its response.
func (t *Target) DecryptQuery(msg Message) (dnsMessage []byte, qc *QueryContext, err error) {
	if msg.Type != MessageTypeQuery {
		return nil, nil, fmt.Errorf("%w: message_type %#02x is not a query", ErrMalformed, msg.Type)
	}
	// Constant-time is unnecessary here and would be cargo-cult: the key ID is
	// public, derived from a published config. What matters is that a mismatch is
	// reported as an AUTHORIZATION failure so the client knows to refetch, not as a
	// decrypt failure it would pointlessly retry.
	if len(msg.KeyID) != len(t.keyID) || string(msg.KeyID) != string(t.keyID) {
		return nil, nil, ErrKeyIDMismatch
	}

	// enc || ct, where enc is the KEM encapsulated key: 32 bytes for X25519.
	if len(msg.Encrypted) <= x25519EncLen {
		return nil, nil, fmt.Errorf("%w: encrypted_message too short to hold enc plus ciphertext", ErrMalformed)
	}
	enc, ct := msg.Encrypted[:x25519EncLen], msg.Encrypted[x25519EncLen:]

	// info is the bare label "odoh query" — NOT the label with the key ID appended.
	// The key ID is bound through the AAD instead. Conflating the two is the
	// classic ODoH interop bug: both sides encrypt successfully against
	// themselves and never against anyone else.
	recipient, err := hpke.NewRecipient(enc, t.hpkePriv, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(labelQuery))
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: setting up HPKE recipient: %w", err)
	}

	plainBytes, err := recipient.Open(queryAAD(msg.KeyID), ct)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: opening query: %w", err)
	}
	p, err := ParsePlaintext(plainBytes)
	if err != nil {
		return nil, nil, err
	}
	return p.DNSMessage, &QueryContext{recipient: recipient, queryPlain: plainBytes}, nil
}

// EncryptResponse encrypts a DNS response for the client that sent qc's query.
//
// padding is included in the plaintext; callers should pad to a fixed bucket so
// response length does not leak which name was asked for. Left to the caller
// because the right bucket depends on what the target serves, and a wrong default
// here would silently weaken every deployment.
func (t *Target) EncryptResponse(qc *QueryContext, dnsResponse, padding []byte) (Message, error) {
	if qc == nil || qc.recipient == nil {
		return Message{}, errors.New("odoh: nil query context")
	}
	respNonce := make([]byte, respNonceLen)
	if _, err := rand.Read(respNonce); err != nil {
		return Message{}, fmt.Errorf("odoh: generating response nonce: %w", err)
	}

	key, nonce, err := deriveResponseSecrets(qc.recipient, qc.queryPlain, respNonce)
	if err != nil {
		return Message{}, err
	}

	plain := Plaintext{DNSMessage: dnsResponse, Padding: padding}.Marshal()
	ct, err := sealAESGCM(key, nonce, responseAAD(respNonce), plain)
	if err != nil {
		return Message{}, err
	}

	// RFC 9230 §8: the response carries the response nonce in the key_id field.
	// It is not a key identifier — reusing the field for it is the spec's choice,
	// and a reader expecting a key ID there will be confused, hence this comment.
	return Message{
		Type:      MessageTypeResponse,
		KeyID:     respNonce,
		Encrypted: ct,
	}, nil
}
