// Package fixture provides deterministic key material and reference
// signers for tests and examples. The signers here are intentionally
// minimal — httpsigcheck is a verifier — but they follow RFC 9421 §3.1
// and RFC 9449 §4 closely enough to fabricate realistic inputs, both
// valid and subtly broken.
//
// Everything is fixed: the Ed25519 key derives from a constant seed and
// the EC/RSA keys are embedded PEM blobs, so fabricated messages are
// reproducible across machines.
package fixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
	"github.com/JaydenCJ/httpsigcheck/internal/sigbase"
)

// Ed25519Seed is the fixed seed for the test Ed25519 keypair.
var Ed25519Seed = []byte("httpsigcheck-fixture-seed-00001!")

// Ed25519Key returns the deterministic test signing key.
func Ed25519Key() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(Ed25519Seed)
}

// Ed25519PublicPEM returns the PKIX PEM of the test public key.
func Ed25519PublicPEM() string {
	der, err := x509.MarshalPKIXPublicKey(Ed25519Key().Public())
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// HMACSecret is the fixed shared secret for hmac-sha256 fixtures.
const HMACSecret = "fixture-shared-secret-for-tests"

// ECP256PrivatePEM is a fixed P-256 key for ECDSA fixtures. Not a
// secret: generated for this repository's tests and examples only —
// never use it for anything real.
const ECP256PrivatePEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICn3ORiezEWknWP0tynnqRtN/cVMf/Mz3Spi7JRAylKjoAoGCCqGSM49
AwEHoUQDQgAER68B0RhicxaQ1UOcKswbl0hDw1IB22uJMielQgUEOXZKoPeVkeqg
JJlJsqPgOEQ1shngAMjyT5xu01+QxWgBgQ==
-----END EC PRIVATE KEY-----
`

// ECP256PublicPEM is the matching public key.
const ECP256PublicPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER68B0RhicxaQ1UOcKswbl0hDw1IB
22uJMielQgUEOXZKoPeVkeqgJJlJsqPgOEQ1shngAMjyT5xu01+QxWgBgQ==
-----END PUBLIC KEY-----
`

// RSAPrivatePEM is a fixed 2048-bit key for RSA fixtures. Not a
// secret: generated for this repository's tests and examples only —
// never use it for anything real.
const RSAPrivatePEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAy44HxPdxX4Kj+KnD8TlCoIWY6ZDFAffeLH6IzLt48Qt/AI0u
T2JTL3gyz6PdUvOqEN2BFyaZQ5jfUDcaa8FnPoAYnGSYKeH2Y+DjqounHUb0BdBn
1rFG/j1sbVhRPHZzg9I3orABIi572FrwWh0s3blOLGp4m5H7USrrkuWME4EHjtT2
zCs3EbwG3HiSWN+J2Ib+eGUs0Udc3xAEoPOCZroZV1aMUkcwVtifBO7BBCsIF5Se
zWCrtjxINdB4rtKqfWURCUhfgHjNArYlDXdbdyslM19ITU0hsru4gLzCldc3fIfk
aikXHGqF4VD4dXrg82z6IuZj4wq5uT0jRfmXXwIDAQABAoIBAA+Bhe/9gCJsG5I2
rxlyE4mSLmrPFLgoqeuucTyp+fWKuvr6G5FVMSGy61P2l0aED0FyTizK9kPi96fu
+qaYuK+sfF4gKkM5K6wXa+BdpmD25bcyVVFSdyZThticMLFave6dwI/hDm+3Jhyo
w28Ukoq1XKd02N5+SVcOiPF2EQHvNdMFLjz1+um1HA41ePj4Ymw35VAFF6/NKwCs
FNoKvoPMAv78r8q6t/MlZJcuGRnc0mYCuDgOd2Vj6ULidcUBOmP7W3TkLkcso3OZ
w83TcuqRXK/5CF8VvbwfY/U7BbgZuiaKle5lnfQdXnhxvaDKHje33NK+Eckb5OdG
gvTxYVkCgYEA2aVNiKr9MWEO22Hn3lz2a5DsX3wgxXBHnEU/syaIEyKmF8TaiNi/
o+ceqWr1Bs+xYm9lZ4R4z3MShBG7NanOSf7SNkc5TeMBMoBU2HSdhmEuDZQumEdH
3SDj2S4zrO3IshbVtCpQWPD4AEb8utprjqetwspNV1o1iIsgj+rQobMCgYEA720K
lnHHUU7V7nDdFPJAfnbvVx08VXz0DcQqY1EcHLsaYBQq0RBHkb3+g+vq6Re++sD/
Svhc9SPMjztcWgl2HBhWRaCGLi0aWM8iEaorjK37N0/cAkkWVfXLxDcnWaDn9rnx
eeurmYTt2eW7ZHb9ZAMzXmOt9e222gPNdTcTpaUCgYA2SM6P2eYQ3N5xxXeptJIZ
vinWnwUleZ3C0lrS+jdSXoACyaygGT+jR9AT/YNj0YWywYoPSbFAPLlPi4SgG9xC
BHa15wnZ7VatG+kNm/h2PeLYrC76+DxqYPuzfZyR8zTthliC+VLU/DU/DHWYvUW6
bQQf44lq0issBVd3zd9/lQKBgCzQoTm1xFQgyIRgFdG04oOJaZVJwKBTyi7FeBWs
+fEayH4RaE5HmM3b3Ub+IrNMoY+4DlEPGf88my54MvobaUMq/wL7YAJGqPbUlpDt
5Ebpzer1hL3cxlSCtIhetnvdVW3mMh/bD/ylWAwAJ0pPx3Av9S6Gw+oTe7VlHtEA
5SmNAoGASIN6DUKLTjBcganjYTsyHCTBCO3H07Wq/hstVaKKSrbapmHJo+BMhrSI
UR2EhSNvY8nR0HJPpCJa11+rJNGuSzdspLioekPODVJTtMFctFmCML71uWxjsUK2
9+5ad5M2rDM77jN9QnZd0UxXbv90LojrcWIX615vkIIdMkm0xj4=
-----END RSA PRIVATE KEY-----
`

// RSAPublicPEM is the matching public key.
const RSAPublicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy44HxPdxX4Kj+KnD8TlC
oIWY6ZDFAffeLH6IzLt48Qt/AI0uT2JTL3gyz6PdUvOqEN2BFyaZQ5jfUDcaa8Fn
PoAYnGSYKeH2Y+DjqounHUb0BdBn1rFG/j1sbVhRPHZzg9I3orABIi572FrwWh0s
3blOLGp4m5H7USrrkuWME4EHjtT2zCs3EbwG3HiSWN+J2Ib+eGUs0Udc3xAEoPOC
ZroZV1aMUkcwVtifBO7BBCsIF5SezWCrtjxINdB4rtKqfWURCUhfgHjNArYlDXdb
dyslM19ITU0hsru4gLzCldc3fIfkaikXHGqF4VD4dXrg82z6IuZj4wq5uT0jRfmX
XwIDAQAB
-----END PUBLIC KEY-----
`

// ECKey parses the fixed P-256 private key.
func ECKey() *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(ECP256PrivatePEM))
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

// RSAKey parses the fixed RSA private key.
func RSAKey() *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(RSAPrivatePEM))
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

// SignBase signs a signature base with the named RFC 9421 algorithm and
// the fixture key for it.
func SignBase(alg, base string) []byte {
	input := []byte(base)
	switch alg {
	case "ed25519":
		return ed25519.Sign(Ed25519Key(), input)
	case "ecdsa-p256-sha256":
		digest := sha256.Sum256(input)
		r, s, err := ecdsa.Sign(rand.Reader, ECKey(), digest[:])
		if err != nil {
			panic(err)
		}
		return rawRS(r, s, 32)
	case "rsa-pss-sha512":
		digest := sha512.Sum512(input)
		sig, err := rsa.SignPSS(rand.Reader, RSAKey(), crypto.SHA512, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			panic(err)
		}
		return sig
	case "rsa-v1_5-sha256":
		digest := sha256.Sum256(input)
		sig, err := rsa.SignPKCS1v15(rand.Reader, RSAKey(), crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	case "hmac-sha256":
		mac := hmac.New(sha256.New, []byte(HMACSecret))
		mac.Write(input)
		return mac.Sum(nil)
	}
	panic("fixture: unknown algorithm " + alg)
}

// rawRS renders an ECDSA signature as fixed-width r||s.
func rawRS(r, s *big.Int, intLen int) []byte {
	out := make([]byte, 2*intLen)
	r.FillBytes(out[:intLen])
	s.FillBytes(out[intLen:])
	return out
}

// SignMessage appends Signature-Input and Signature fields to a raw
// HTTP message, signing the base built from coveredWithParams (an inner
// list such as `("@method" "@path");created=1;keyid="k"`).
func SignMessage(raw, label, coveredWithParams, alg string) string {
	msg, err := httpmsg.Parse([]byte(raw))
	if err != nil {
		panic(fmt.Sprintf("fixture: unparsable message: %v", err))
	}
	covered, err := sfv.ParseInnerList(coveredWithParams)
	if err != nil {
		panic(fmt.Sprintf("fixture: unparsable covered components: %v", err))
	}
	base, err := sigbase.Build(msg, covered, sigbase.Options{})
	if err != nil {
		panic(fmt.Sprintf("fixture: cannot build base: %v", err))
	}
	sig := SignBase(alg, base.Text())
	return AddSignatureHeaders(raw, label, base.ParamsLine, sig)
}

// AddSignatureHeaders splices Signature-Input/Signature fields into a
// raw message just before the blank line, leaving everything else
// byte-identical.
func AddSignatureHeaders(raw, label, paramsLine string, sig []byte) string {
	headers := fmt.Sprintf("Signature-Input: %s=%s\nSignature: %s=:%s:",
		label, paramsLine, label, base64.StdEncoding.EncodeToString(sig))
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := strings.Index(raw, sep); i >= 0 {
			nl := "\n"
			if sep == "\r\n\r\n" {
				nl = "\r\n"
				headers = strings.ReplaceAll(headers, "\n", "\r\n")
			}
			return raw[:i] + nl + headers + raw[i:]
		}
	}
	return strings.TrimRight(raw, "\n") + "\n" + headers + "\n\n"
}

// ContentDigest returns a Content-Digest field value for a body.
func ContentDigest(alg string, body []byte) string {
	var sum []byte
	switch alg {
	case "sha-256":
		s := sha256.Sum256(body)
		sum = s[:]
	case "sha-512":
		s := sha512.Sum512(body)
		sum = s[:]
	default:
		panic("fixture: unknown digest algorithm " + alg)
	}
	return fmt.Sprintf("%s=:%s:", alg, base64.StdEncoding.EncodeToString(sum))
}

// ECJWK returns the public JWK object for the fixture P-256 key.
func ECJWK() map[string]any {
	pub := ECKey().PublicKey
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pad32(pub.X)),
		"y":   base64.RawURLEncoding.EncodeToString(pad32(pub.Y)),
	}
}

// Ed25519JWK returns the public JWK object for the fixture Ed25519 key.
func Ed25519JWK() map[string]any {
	pub := Ed25519Key().Public().(ed25519.PublicKey)
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func pad32(n *big.Int) []byte {
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

// DPoPProof builds a DPoP proof JWT signed with a fixture key.
// alg is "ES256" or "EdDSA"; header and claims can be overridden or
// extended (a nil value in override deletes the member).
func DPoPProof(alg string, claims map[string]any, headerOverride map[string]any) string {
	header := map[string]any{"typ": "dpop+jwt", "alg": alg}
	switch alg {
	case "ES256":
		header["jwk"] = ECJWK()
	case "EdDSA":
		header["jwk"] = Ed25519JWK()
	default:
		panic("fixture: unsupported DPoP alg " + alg)
	}
	for k, v := range headerOverride {
		if v == nil {
			delete(header, k)
		} else {
			header[k] = v
		}
	}
	h := b64uJSON(header)
	c := b64uJSON(claims)
	signingInput := h + "." + c

	var sig []byte
	switch header["alg"] {
	case "ES256":
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, ECKey(), digest[:])
		if err != nil {
			panic(err)
		}
		sig = rawRS(r, s, 32)
	default:
		sig = ed25519.Sign(Ed25519Key(), []byte(signingInput))
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64uJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
