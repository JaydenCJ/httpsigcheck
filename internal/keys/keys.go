// Package keys loads verification keys from PEM files, JWK documents,
// and shared-secret strings, and computes RFC 7638 JWK thumbprints.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// Key is a loaded verification key.
type Key struct {
	// Kind is a human-readable key type: "ed25519", "ecdsa-p256",
	// "ecdsa-p384", "ecdsa-p521", "rsa-2048", "hmac".
	Kind string
	// KeyID is the JWK "kid", when the key came from a JWK that had one.
	KeyID string

	Ed25519 ed25519.PublicKey
	ECDSA   *ecdsa.PublicKey
	RSA     *rsa.PublicKey
	Secret  []byte // HMAC shared secret
}

// LoadPublic parses a public key from raw file bytes. It accepts, in
// order of detection: a JWK JSON document, a PEM "PUBLIC KEY" (PKIX),
// a PEM "RSA PUBLIC KEY" (PKCS#1), or a PEM "CERTIFICATE" (the
// certificate's subject key is extracted; no chain validation happens —
// this is an offline verifier, not a CA).
func LoadPublic(data []byte) (*Key, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		return ParseJWK([]byte(trimmed))
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key file is neither a JWK document nor PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKIX public key: %w", err)
		}
		return fromCryptoPublic(pub)
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#1 public key: %w", err)
		}
		return fromCryptoPublic(pub)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		return fromCryptoPublic(cert.PublicKey)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q (want PUBLIC KEY, RSA PUBLIC KEY, or CERTIFICATE)", block.Type)
	}
}

// Shared builds an HMAC key from a --secret flag value. A "base64:"
// prefix marks a standard-base64 secret; anything else is used as raw
// bytes.
func Shared(s string) (*Key, error) {
	if enc, ok := strings.CutPrefix(s, "base64:"); ok {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 secret: %w", err)
		}
		return &Key{Kind: "hmac", Secret: raw}, nil
	}
	if s == "" {
		return nil, fmt.Errorf("shared secret is empty")
	}
	return &Key{Kind: "hmac", Secret: []byte(s)}, nil
}

func fromCryptoPublic(pub any) (*Key, error) {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return &Key{Kind: "ed25519", Ed25519: p}, nil
	case *ecdsa.PublicKey:
		switch p.Curve.Params().Name {
		case "P-256":
			return &Key{Kind: "ecdsa-p256", ECDSA: p}, nil
		case "P-384":
			return &Key{Kind: "ecdsa-p384", ECDSA: p}, nil
		case "P-521":
			return &Key{Kind: "ecdsa-p521", ECDSA: p}, nil
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve %q", p.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return &Key{Kind: fmt.Sprintf("rsa-%d", p.N.BitLen()), RSA: p}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// IsRSA reports whether the key is an RSA public key.
func (k *Key) IsRSA() bool { return k.RSA != nil }
