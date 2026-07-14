// Tests for key loading (PEM, JWK, shared secrets) and RFC 7638
// thumbprints. Wrong key parsing fails verification in confusing ways,
// so every accepted format has a positive and a negative case.
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
)

func TestLoadPEMPublicKeys(t *testing.T) {
	cases := []struct {
		name string
		pem  string
		kind string
	}{
		{"ed25519", fixture.Ed25519PublicPEM(), "ed25519"},
		{"ecdsa p-256", fixture.ECP256PublicPEM, "ecdsa-p256"},
		{"rsa 2048", fixture.RSAPublicPEM, "rsa-2048"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := LoadPublic([]byte(c.pem))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if k.Kind != c.kind {
				t.Fatalf("kind = %s, want %s", k.Kind, c.kind)
			}
		})
	}
	k, err := LoadPublic([]byte(fixture.Ed25519PublicPEM()))
	if err != nil || len(k.Ed25519) != ed25519.PublicKeySize {
		t.Fatalf("ed25519 material: %v, %d bytes", err, len(k.Ed25519))
	}
}

func TestLoadCertificateExtractsSubjectKey(t *testing.T) {
	// Open-banking deployments often hand you a certificate, not a
	// bare key; the subject public key must come out usable.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sig.example.test"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	priv := fixture.Ed25519Key()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	k, err := LoadPublic(pemBytes)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if k.Kind != "ed25519" || !bytes.Equal(k.Ed25519, priv.Public().(ed25519.PublicKey)) {
		t.Fatal("certificate subject key does not match the signing key")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	if _, err := LoadPublic([]byte("not a key at all")); err == nil {
		t.Fatal("garbage must be rejected")
	}
	if _, err := LoadPublic([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("unsupported PEM block type must be rejected")
	}
}

func TestParseJWKECWithKid(t *testing.T) {
	jwk := fixture.ECJWK()
	jwk["kid"] = "client-key-1"
	raw, _ := json.Marshal(jwk)
	k, err := LoadPublic(raw) // JWK detection happens inside LoadPublic
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if k.Kind != "ecdsa-p256" || k.KeyID != "client-key-1" {
		t.Fatalf("kind=%s kid=%q", k.Kind, k.KeyID)
	}
}

func TestParseJWKRejectsOffCurvePoint(t *testing.T) {
	jwk := fixture.ECJWK()
	// Flip the y coordinate to a value that is not on P-256.
	jwk["y"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	raw, _ := json.Marshal(jwk)
	if _, err := ParseJWK(raw); err == nil {
		t.Fatal("off-curve point must be rejected (invalid-curve attacks)")
	}
}

func TestParseJWKRejectsBrokenDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"no kty":          `{"crv":"P-256"}`,
		"EC without x":    `{"kty":"EC","crv":"P-256","y":"AA"}`,
		"RSA e range":     `{"kty":"RSA","n":"AQAB","e":"AQ"}`,
		"unknown kty":     `{"kty":"XYZ"}`,
		"short Ed25519 x": `{"kty":"OKP","crv":"Ed25519","x":"c2hvcnQ"}`,
		"unsupported OKP": `{"kty":"OKP","crv":"X25519","x":"AA"}`,
	} {
		if _, err := ParseJWK([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSharedSecretRawAndBase64(t *testing.T) {
	k, err := Shared("plain-secret")
	if err != nil || string(k.Secret) != "plain-secret" {
		t.Fatalf("raw secret: %v %q", err, k.Secret)
	}
	k, err = Shared("base64:aGVsbG8=")
	if err != nil || string(k.Secret) != "hello" {
		t.Fatalf("base64 secret: %v %q", err, k.Secret)
	}
	if _, err := Shared("base64:!!!"); err == nil {
		t.Fatal("invalid base64 must be rejected")
	}
	if _, err := Shared(""); err == nil {
		t.Fatal("empty secret must be rejected")
	}
}

func TestThumbprintMatchesIndependentComputation(t *testing.T) {
	// Compute the RFC 7638 canonical form by hand here, so the
	// implementation's member selection and ordering are checked
	// against the spec, not against itself.
	jwk := fixture.ECJWK()
	canonical := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"].(string) + `","y":"` + jwk["y"].(string) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	got, err := Thumbprint(jwk)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got != want {
		t.Fatalf("thumbprint %s, want %s", got, want)
	}
	// kid, use, alg must not change the thumbprint — only the required
	// members participate in the RFC 7638 canonical form.
	decorated := fixture.ECJWK()
	decorated["kid"] = "some-kid"
	decorated["use"] = "sig"
	got2, err := Thumbprint(decorated)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got2 != got {
		t.Fatal("optional members changed the thumbprint")
	}
}

func TestHasPrivateMaterialDetectsLeaks(t *testing.T) {
	pub := fixture.ECJWK()
	if HasPrivateMaterial(pub) {
		t.Fatal("public JWK flagged as private")
	}
	leaky := fixture.ECJWK()
	leaky["d"] = "c2VjcmV0"
	if !HasPrivateMaterial(leaky) {
		t.Fatal("JWK with d must be flagged")
	}
	symmetric := map[string]any{"kty": "oct", "k": "c2VjcmV0"}
	if !HasPrivateMaterial(symmetric) {
		t.Fatal("oct JWK must be flagged (symmetric key in a proof)")
	}
}
