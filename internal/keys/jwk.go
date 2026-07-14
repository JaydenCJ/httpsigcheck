package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// jwkFields is the union of the JWK members this tool reads. Private
// members are decoded only so their *presence* can be detected and
// rejected where required (DPoP proofs must embed public keys only).
type jwkFields struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
	K   string `json:"k"`
	D   string `json:"d"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

// ParseJWK parses a JWK JSON document into a verification key.
func ParseJWK(data []byte) (*Key, error) {
	var f jwkFields
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing JWK JSON: %w", err)
	}
	return jwkToKey(f)
}

// ParseJWKMap converts an already-decoded JWK object (as found in a
// DPoP proof header) into a verification key.
func ParseJWKMap(m map[string]any) (*Key, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return ParseJWK(raw)
}

// HasPrivateMaterial reports whether a decoded JWK object carries
// private-key members. RFC 9449 §4.2 forbids these inside DPoP proofs.
func HasPrivateMaterial(m map[string]any) bool {
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := m[member]; ok {
			return true
		}
	}
	return false
}

func jwkToKey(f jwkFields) (*Key, error) {
	switch f.Kty {
	case "OKP":
		if f.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q (only Ed25519)", f.Crv)
		}
		x, err := b64uField("x", f.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 JWK x must be 32 bytes, got %d", len(x))
		}
		return &Key{Kind: "ed25519", KeyID: f.Kid, Ed25519: ed25519.PublicKey(x)}, nil
	case "EC":
		curve, kind, err := curveFor(f.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uField("x", f.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uField("y", f.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("EC JWK point is not on curve %s", f.Crv)
		}
		return &Key{Kind: kind, KeyID: f.Kid, ECDSA: pub}, nil
	case "RSA":
		n, err := b64uField("n", f.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uField("e", f.E)
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64() > 1<<31-1 {
			return nil, fmt.Errorf("RSA JWK exponent out of range")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}
		return &Key{Kind: fmt.Sprintf("rsa-%d", pub.N.BitLen()), KeyID: f.Kid, RSA: pub}, nil
	case "oct":
		k, err := b64uField("k", f.K)
		if err != nil {
			return nil, err
		}
		return &Key{Kind: "hmac", KeyID: f.Kid, Secret: k}, nil
	case "":
		return nil, fmt.Errorf("JWK is missing the required kty member")
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", f.Kty)
	}
}

func curveFor(crv string) (elliptic.Curve, string, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), "ecdsa-p256", nil
	case "P-384":
		return elliptic.P384(), "ecdsa-p384", nil
	case "P-521":
		return elliptic.P521(), "ecdsa-p521", nil
	default:
		return nil, "", fmt.Errorf("unsupported EC curve %q", crv)
	}
}

func b64uField(name, v string) ([]byte, error) {
	if v == "" {
		return nil, fmt.Errorf("JWK is missing the required %s member", name)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("JWK member %s is not base64url: %w", name, err)
	}
	return raw, nil
}

// Thumbprint computes the RFC 7638 JWK thumbprint (base64url of the
// SHA-256 of the canonical required-members-only JSON). This is the
// value bound into access tokens as cnf.jkt.
func Thumbprint(m map[string]any) (string, error) {
	kty, _ := m["kty"].(string)
	var canonical string
	switch kty {
	case "EC":
		crv, x, y := str(m, "crv"), str(m, "x"), str(m, "y")
		if crv == "" || x == "" || y == "" {
			return "", fmt.Errorf("EC JWK thumbprint needs crv, x, and y")
		}
		canonical = fmt.Sprintf(`{"crv":%s,"kty":"EC","x":%s,"y":%s}`, jstr(crv), jstr(x), jstr(y))
	case "OKP":
		crv, x := str(m, "crv"), str(m, "x")
		if crv == "" || x == "" {
			return "", fmt.Errorf("OKP JWK thumbprint needs crv and x")
		}
		canonical = fmt.Sprintf(`{"crv":%s,"kty":"OKP","x":%s}`, jstr(crv), jstr(x))
	case "RSA":
		e, n := str(m, "e"), str(m, "n")
		if e == "" || n == "" {
			return "", fmt.Errorf("RSA JWK thumbprint needs e and n")
		}
		canonical = fmt.Sprintf(`{"e":%s,"kty":"RSA","n":%s}`, jstr(e), jstr(n))
	case "":
		return "", fmt.Errorf("JWK is missing the required kty member")
	default:
		return "", fmt.Errorf("no thumbprint rule for kty %q", kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// jstr JSON-encodes a string. The thumbprint members are base64url and
// curve names, so escaping never actually fires, but correctness is
// cheap.
func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
