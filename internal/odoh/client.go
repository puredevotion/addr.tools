package odoh

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
)

// Client is the RFC 9230 client role.
//
// Present for two reasons, only one of which is testing. It makes the round-trip
// verifiable against the target in this same package — necessary but weak evidence,
// since a symmetric misreading of the spec passes. The real reason is that the lab
// needs a client to MEASURE with: to demonstrate the oblivious path works, something
// has to send a query through a proxy and check what came back.

// Client holds one target's config and the per-query state between sending a query
// and opening its response.
type Client struct {
	config ConfigContents
	keyID  []byte
}

// NewClient prepares a client for a target config, rejecting suites it cannot use.
func NewClient(config ConfigContents) (*Client, error) {
	if config.KEMID != KEMX25519HKDFSHA256 || config.KDFID != KDFHKDFSHA256 || config.AEADID != AEADAES128GCM {
		return nil, fmt.Errorf("%w: kem %#04x kdf %#04x aead %#04x",
			ErrUnsupportedSuite, config.KEMID, config.KDFID, config.AEADID)
	}
	if len(config.PublicKey) == 0 {
		return nil, fmt.Errorf("%w: empty public key", ErrMalformed)
	}
	keyID, err := config.KeyID()
	if err != nil {
		return nil, err
	}
	return &Client{config: config, keyID: keyID}, nil
}

// PendingQuery is the state a client must keep to open the response.
//
// It holds the HPKE sender context and the exact query plaintext, because RFC 9230
// binds the response keys to both. It is single-use: reusing it across queries
// would derive the wrong response key and, worse, would reuse an AEAD nonce.
type PendingQuery struct {
	sender     *hpke.Sender
	queryPlain []byte
}

// EncryptQuery seals a DNS query for the target.
//
// padding is included in the plaintext. Callers should pad to a fixed bucket:
// without it the ciphertext length leaks the query length, and through an oblivious
// proxy that is the main thing left to leak.
func (c *Client) EncryptQuery(dnsQuery, padding []byte) (Message, *PendingQuery, error) {
	if len(dnsQuery) == 0 {
		return Message{}, nil, fmt.Errorf("%w: empty dns query", ErrMalformed)
	}
	pub, err := ecdh.X25519().NewPublicKey(c.config.PublicKey)
	if err != nil {
		return Message{}, nil, fmt.Errorf("odoh: target public key: %w", err)
	}
	hpkePub, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return Message{}, nil, fmt.Errorf("odoh: wrapping target key: %w", err)
	}

	// info is the bare "odoh query" label; the key ID is bound via the AAD below.
	enc, sender, err := hpke.NewSender(hpkePub, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(labelQuery))
	if err != nil {
		return Message{}, nil, fmt.Errorf("odoh: hpke sender: %w", err)
	}

	queryPlain := Plaintext{DNSMessage: dnsQuery, Padding: padding}.Marshal()
	ct, err := sender.Seal(queryAAD(c.keyID), queryPlain)
	if err != nil {
		return Message{}, nil, fmt.Errorf("odoh: sealing query: %w", err)
	}

	return Message{
			Type:      MessageTypeQuery,
			KeyID:     c.keyID,
			Encrypted: append(enc, ct...),
		}, &PendingQuery{
			sender:     sender,
			queryPlain: queryPlain,
		}, nil
}

// DecryptResponse opens the target's response.
//
// The response nonce travels in the message's key_id field. That is RFC 9230 §8's
// choice, not a mistake here: the field is reused, and reading it as a key
// identifier is the obvious misinterpretation.
func (c *Client) DecryptResponse(pq *PendingQuery, msg Message) ([]byte, error) {
	if pq == nil || pq.sender == nil {
		return nil, errors.New("odoh: nil pending query")
	}
	if msg.Type != MessageTypeResponse {
		return nil, fmt.Errorf("%w: message_type %#02x is not a response", ErrMalformed, msg.Type)
	}
	respNonce := msg.KeyID
	if len(respNonce) != respNonceLen {
		return nil, fmt.Errorf("%w: response nonce is %d bytes, want %d", ErrMalformed, len(respNonce), respNonceLen)
	}

	key, nonce, err := deriveResponseSecrets(pq.sender, pq.queryPlain, respNonce)
	if err != nil {
		return nil, err
	}
	plainBytes, err := openAESGCM(key, nonce, responseAAD(respNonce), msg.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("odoh: opening response: %w", err)
	}
	p, err := ParsePlaintext(plainBytes)
	if err != nil {
		return nil, err
	}
	return p.DNSMessage, nil
}
