package odoh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// The RFC 9230 label strings and AAD constructions, isolated here because every
// one of them is a silent interop failure if wrong: both sides encrypt and decrypt
// happily against themselves and never against each other.

const (
	// labelQuery is the HPKE info for query setup: SetupBaseS(pkR, "odoh query").
	// The bare label — the key ID is bound through the AAD, not the info.
	labelQuery = "odoh query"
	// labelResponse is the HPKE exporter context for response key derivation.
	labelResponse = "odoh response"
	// labelKey and labelNonce expand the response PRK.
	labelKey   = "odoh key"
	labelNonce = "odoh nonce"

	// x25519EncLen is the KEM encapsulated key length for DHKEM(X25519).
	x25519EncLen = 32
)

// aadLen renders a length into the two bytes the AAD format uses, saturating at
// the maximum rather than wrapping.
//
// Saturation is safe HERE and nowhere else in this package: the AAD is
// authenticated data, not a parsed length prefix, so both sides compute it from
// values they already hold. A key ID or nonce long enough to overflow could only
// come from our own code, and a wrapped length would silently produce an AAD that
// authenticates something other than what was sent. Callers pass fixed-size values
// (32-byte key IDs, 16-byte nonces), so the bound is unreachable in practice and
// exists so it cannot become reachable unnoticed.
func aadLen(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(n)
}

// queryAAD is RFC 9230 §6.2's `aad = 0x01 || len(key_id) || key_id`.
//
// The length is two bytes, matching the wire encoding of the same field. A
// one-byte length here is the obvious misreading and produces a valid-looking AAD
// that no other implementation computes.
func queryAAD(keyID []byte) []byte {
	b := []byte{MessageTypeQuery}
	b = binary.BigEndian.AppendUint16(b, aadLen(len(keyID)))
	return append(b, keyID...)
}

// responseAAD is RFC 9230 §6.2's `aad = 0x02 || len(resp_nonce) || resp_nonce`.
func responseAAD(respNonce []byte) []byte {
	b := []byte{MessageTypeResponse}
	b = binary.BigEndian.AppendUint16(b, aadLen(len(respNonce)))
	return append(b, respNonce...)
}

// deriveResponseSecrets implements RFC 9230 §6.2's derive_secrets:
//
//	secret = context.Export("odoh response", Nk)
//	salt   = Q_plain || len(resp_nonce) || resp_nonce
//	prk    = Extract(salt, secret)
//	key    = Expand(prk, "odoh key", Nk)
//	nonce  = Expand(prk, "odoh nonce", Nn)
//
// Two things here are easy to get backwards and neither fails loudly:
//
//  1. Q_plain is the FULL ObliviousDoHMessagePlaintext — the length-prefixed DNS
//     message and its padding — not the bare DNS message. Binding the response to
//     the padded query is deliberate.
//  2. Extract's arguments. The spec writes Extract(salt, secret), so the salt is
//     the query-derived value and the SECRET is the HPKE export. Go's
//     hkdf.Extract(h, secret, salt) takes them in the opposite order, so passing
//     them positionally as written yields a stable, wrong PRK.
func deriveResponseSecrets(ctx exporter, queryPlain, respNonce []byte) (key, nonce []byte, err error) {
	secret, err := ctx.Export(labelResponse, nk)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: exporting response secret: %w", err)
	}

	salt := make([]byte, 0, len(queryPlain)+2+len(respNonce))
	salt = append(salt, queryPlain...)
	salt = binary.BigEndian.AppendUint16(salt, aadLen(len(respNonce)))
	salt = append(salt, respNonce...)

	// Note the argument order against the spec's Extract(salt, secret).
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("odoh: extracting response prk: %w", err)
	}

	if key, err = hkdf.Expand(sha256.New, prk, labelKey, nk); err != nil {
		return nil, nil, fmt.Errorf("odoh: expanding response key: %w", err)
	}
	if nonce, err = hkdf.Expand(sha256.New, prk, labelNonce, nn); err != nil {
		return nil, nil, fmt.Errorf("odoh: expanding response nonce: %w", err)
	}
	return key, nonce, nil
}

// exporter is the HPKE export capability both Sender and Recipient provide, so the
// same derivation serves the client and target halves and cannot drift apart.
type exporter interface {
	Export(context string, length int) ([]byte, error)
}

var _ exporter = (*hpke.Recipient)(nil)
var _ exporter = (*hpke.Sender)(nil)

func sealAESGCM(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func openAESGCM(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("odoh: aes: %w", err)
	}
	// NewGCM gives the standard 12-byte nonce, which is what Nn is above. Using
	// NewGCMWithNonceSize would silently accept a wrong-length nonce.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("odoh: gcm: %w", err)
	}
	return aead, nil
}
