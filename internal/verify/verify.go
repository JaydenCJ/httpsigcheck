// Package verify checks signature bytes against a reconstructed signing
// input, implementing every algorithm RFC 9421 registers plus the JWS
// algorithms DPoP proofs use. All primitives come from the Go standard
// library; nothing here ever touches the network.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/JaydenCJ/httpsigcheck/internal/keys"
)

// Algorithm names from the RFC 9421 HTTP Signature Algorithms registry.
const (
	AlgRSAPSS512  = "rsa-pss-sha512"
	AlgRSAv15_256 = "rsa-v1_5-sha256"
	AlgHMAC256    = "hmac-sha256"
	AlgECDSA256   = "ecdsa-p256-sha256"
	AlgECDSA384   = "ecdsa-p384-sha384"
	AlgEd25519    = "ed25519"
)

// ForKey infers the RFC 9421 algorithm from a key's type. RSA keys are
// ambiguous (PSS vs PKCS#1 v1.5), so the registry default rsa-pss-sha512
// is chosen and the caller reports the assumption.
func ForKey(k *keys.Key) (string, error) {
	switch {
	case k.Ed25519 != nil:
		return AlgEd25519, nil
	case k.ECDSA != nil:
		switch k.Kind {
		case "ecdsa-p256":
			return AlgECDSA256, nil
		case "ecdsa-p384":
			return AlgECDSA384, nil
		default:
			return "", fmt.Errorf("no RFC 9421 algorithm is registered for %s keys", k.Kind)
		}
	case k.RSA != nil:
		return AlgRSAPSS512, nil
	case k.Secret != nil:
		return AlgHMAC256, nil
	}
	return "", fmt.Errorf("key has no usable material")
}

// CompatibleWithKey reports whether an algorithm name can be used with
// the given key, catching key/alg confusion before any crypto runs.
func CompatibleWithKey(alg string, k *keys.Key) error {
	want := ""
	switch alg {
	case AlgEd25519:
		if k.Ed25519 == nil {
			want = "an Ed25519 key"
		}
	case AlgECDSA256:
		if k.ECDSA == nil || k.Kind != "ecdsa-p256" {
			want = "an ECDSA P-256 key"
		}
	case AlgECDSA384:
		if k.ECDSA == nil || k.Kind != "ecdsa-p384" {
			want = "an ECDSA P-384 key"
		}
	case AlgRSAPSS512, AlgRSAv15_256:
		if k.RSA == nil {
			want = "an RSA key"
		}
	case AlgHMAC256:
		if k.Secret == nil {
			want = "a shared secret (--secret)"
		}
	default:
		return fmt.Errorf("unknown signature algorithm %q (registered: rsa-pss-sha512, rsa-v1_5-sha256, hmac-sha256, ecdsa-p256-sha256, ecdsa-p384-sha384, ed25519)", alg)
	}
	if want != "" {
		return fmt.Errorf("algorithm %s requires %s, but the provided key is %s", alg, want, k.Kind)
	}
	return nil
}

// Signature verifies sig over input with the named RFC 9421 algorithm.
// A nil return means the signature is genuine over exactly these bytes.
func Signature(alg string, k *keys.Key, input, sig []byte) error {
	if err := CompatibleWithKey(alg, k); err != nil {
		return err
	}
	switch alg {
	case AlgEd25519:
		if len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("ed25519 signatures are 64 bytes, got %d", len(sig))
		}
		if !ed25519.Verify(k.Ed25519, input, sig) {
			return fmt.Errorf("ed25519 signature does not verify")
		}
		return nil
	case AlgECDSA256:
		digest := sha256.Sum256(input)
		return ecdsaVerify(k.ECDSA, digest[:], sig, 32)
	case AlgECDSA384:
		digest := sha512.Sum384(input)
		return ecdsaVerify(k.ECDSA, digest[:], sig, 48)
	case AlgRSAPSS512:
		digest := sha512.Sum512(input)
		// Salt length is detected from the signature; RFC 9421 signers
		// use hash-length salts, but verification stays permissive.
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512}
		if err := rsa.VerifyPSS(k.RSA, crypto.SHA512, digest[:], sig, opts); err != nil {
			return fmt.Errorf("rsa-pss-sha512 signature does not verify")
		}
		return nil
	case AlgRSAv15_256:
		digest := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(k.RSA, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("rsa-v1_5-sha256 signature does not verify")
		}
		return nil
	case AlgHMAC256:
		mac := hmac.New(sha256.New, k.Secret)
		mac.Write(input)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return fmt.Errorf("hmac-sha256 tag does not match")
		}
		return nil
	}
	return fmt.Errorf("unknown signature algorithm %q", alg)
}

// ecdsaVerify checks a raw r||s signature (RFC 9421 §3.3.3/§3.3.4 and
// JWS both use this fixed-width concatenation, not ASN.1 DER).
func ecdsaVerify(pub *ecdsa.PublicKey, digest, sig []byte, intLen int) error {
	if len(sig) != 2*intLen {
		return fmt.Errorf("ECDSA signature must be %d bytes of concatenated r||s, got %d (ASN.1 DER signatures are not valid here)", 2*intLen, len(sig))
	}
	r := new(big.Int).SetBytes(sig[:intLen])
	s := new(big.Int).SetBytes(sig[intLen:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return fmt.Errorf("ECDSA signature does not verify")
	}
	return nil
}

// JWS verifies a JWS signature for the algorithms DPoP allows. alg is
// the JOSE name (ES256, RS256, PS256, EdDSA, ...).
func JWS(alg string, k *keys.Key, signingInput, sig []byte) error {
	switch alg {
	case "EdDSA":
		return Signature(AlgEd25519, k, signingInput, sig)
	case "ES256":
		return Signature(AlgECDSA256, k, signingInput, sig)
	case "ES384":
		return Signature(AlgECDSA384, k, signingInput, sig)
	case "ES512":
		if k.ECDSA == nil || k.Kind != "ecdsa-p521" {
			return fmt.Errorf("algorithm ES512 requires an ECDSA P-521 key, but the embedded key is %s", k.Kind)
		}
		digest := sha512.Sum512(signingInput)
		return ecdsaVerify(k.ECDSA, digest[:], sig, 66)
	case "RS256":
		if k.RSA == nil {
			return fmt.Errorf("algorithm RS256 requires an RSA key, but the embedded key is %s", k.Kind)
		}
		digest := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(k.RSA, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("RS256 signature does not verify")
		}
		return nil
	case "PS256":
		if k.RSA == nil {
			return fmt.Errorf("algorithm PS256 requires an RSA key, but the embedded key is %s", k.Kind)
		}
		digest := sha256.Sum256(signingInput)
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
		if err := rsa.VerifyPSS(k.RSA, crypto.SHA256, digest[:], sig, opts); err != nil {
			return fmt.Errorf("PS256 signature does not verify")
		}
		return nil
	case "none":
		return fmt.Errorf(`alg "none" is forbidden: an unsigned proof proves nothing`)
	case "HS256", "HS384", "HS512":
		return fmt.Errorf("symmetric JWS algorithm %s is forbidden for DPoP (RFC 9449 §4.2 requires an asymmetric algorithm)", alg)
	default:
		return fmt.Errorf("unsupported JWS algorithm %q (supported: ES256, ES384, ES512, RS256, PS256, EdDSA)", alg)
	}
}
