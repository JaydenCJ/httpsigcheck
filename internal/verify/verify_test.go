// Tests for the cryptographic verification layer: every RFC 9421
// algorithm and every DPoP JWS algorithm, positive and negative. All
// signing happens in-process with fixed fixture keys.
package verify

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
	"github.com/JaydenCJ/httpsigcheck/internal/keys"
)

const base = "\"@method\": POST\n\"@signature-params\": (\"@method\");created=1618884473"

func ed25519Key(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.LoadPublic([]byte(fixture.Ed25519PublicPEM()))
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return k
}

func ecKey(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.LoadPublic([]byte(fixture.ECP256PublicPEM))
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return k
}

func rsaKey(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.LoadPublic([]byte(fixture.RSAPublicPEM))
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return k
}

func TestEd25519VerifiesAndDetectsTampering(t *testing.T) {
	sig := fixture.SignBase(AlgEd25519, base)
	if err := Signature(AlgEd25519, ed25519Key(t), []byte(base), sig); err != nil {
		t.Fatalf("genuine signature rejected: %v", err)
	}
	// One flipped byte in the input must break it.
	tampered := "X" + base[1:]
	if err := Signature(AlgEd25519, ed25519Key(t), []byte(tampered), sig); err == nil {
		t.Fatal("tampered input accepted")
	}
	// One flipped byte in the signature must break it.
	sig[0] ^= 0xff
	if err := Signature(AlgEd25519, ed25519Key(t), []byte(base), sig); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestECDSAP256VerifiesRawRS(t *testing.T) {
	sig := fixture.SignBase(AlgECDSA256, base)
	if len(sig) != 64 {
		t.Fatalf("fixture must sign r||s (64 bytes), got %d", len(sig))
	}
	if err := Signature(AlgECDSA256, ecKey(t), []byte(base), sig); err != nil {
		t.Fatalf("genuine signature rejected: %v", err)
	}
	if err := Signature(AlgECDSA256, ecKey(t), []byte(base+"x"), sig); err == nil {
		t.Fatal("tampered input accepted")
	}
}

func TestECDSARejectsDERWithHint(t *testing.T) {
	// A 70-byte ASN.1 DER blob is the classic interop mistake; the
	// error must say what is wrong, not just "invalid".
	err := Signature(AlgECDSA256, ecKey(t), []byte(base), make([]byte, 70))
	if err == nil || !strings.Contains(err.Error(), "ASN.1") {
		t.Fatalf("want an ASN.1 hint for wrong-length ECDSA sig, got: %v", err)
	}
}

func TestRSABothSchemesVerifyAndDoNotCross(t *testing.T) {
	pss := fixture.SignBase(AlgRSAPSS512, base)
	if err := Signature(AlgRSAPSS512, rsaKey(t), []byte(base), pss); err != nil {
		t.Fatalf("genuine PSS signature rejected: %v", err)
	}
	// A PSS signature must not pass PKCS#1 v1.5 verification.
	if err := Signature(AlgRSAv15_256, rsaKey(t), []byte(base), pss); err == nil {
		t.Fatal("PSS signature accepted as v1.5")
	}
	v15 := fixture.SignBase(AlgRSAv15_256, base)
	if err := Signature(AlgRSAv15_256, rsaKey(t), []byte(base), v15); err != nil {
		t.Fatalf("genuine v1.5 signature rejected: %v", err)
	}
	if err := Signature(AlgRSAv15_256, rsaKey(t), []byte(base+"x"), v15); err == nil {
		t.Fatal("tampered input accepted")
	}
}

func TestHMACVerifiesAndRejectsWrongSecret(t *testing.T) {
	key := &keys.Key{Kind: "hmac", Secret: []byte(fixture.HMACSecret)}
	sig := fixture.SignBase(AlgHMAC256, base)
	if err := Signature(AlgHMAC256, key, []byte(base), sig); err != nil {
		t.Fatalf("genuine tag rejected: %v", err)
	}
	wrong := &keys.Key{Kind: "hmac", Secret: []byte("other-secret")}
	if err := Signature(AlgHMAC256, wrong, []byte(base), sig); err == nil {
		t.Fatal("tag accepted with the wrong secret")
	}
}

func TestForKeyInference(t *testing.T) {
	cases := []struct {
		key  *keys.Key
		want string
	}{
		{ed25519Key(t), AlgEd25519},
		{ecKey(t), AlgECDSA256},
		{rsaKey(t), AlgRSAPSS512}, // registry default for ambiguous RSA
		{&keys.Key{Kind: "hmac", Secret: []byte("s")}, AlgHMAC256},
	}
	for _, c := range cases {
		got, err := ForKey(c.key)
		if err != nil || got != c.want {
			t.Errorf("ForKey(%s) = %q, %v; want %q", c.key.Kind, got, err, c.want)
		}
	}
}

func TestCompatibleWithKeyCatchesConfusion(t *testing.T) {
	// alg is attacker-controlled input; a mismatch against the key
	// must be a hard error before any crypto runs.
	if err := CompatibleWithKey(AlgEd25519, rsaKey(t)); err == nil {
		t.Fatal("ed25519 alg with an RSA key must be rejected")
	}
	if err := CompatibleWithKey(AlgECDSA384, ecKey(t)); err == nil {
		t.Fatal("p384 alg with a p256 key must be rejected")
	}
	if err := CompatibleWithKey(AlgHMAC256, ed25519Key(t)); err == nil {
		t.Fatal("hmac alg with an asymmetric key must be rejected")
	}
}

func TestUnknownAlgorithmListsRegistered(t *testing.T) {
	err := Signature("quantum-9000", ed25519Key(t), []byte(base), nil)
	if err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("unknown algorithm error should list the registry: %v", err)
	}
}

func TestJWSAlgorithms(t *testing.T) {
	input := []byte("header.payload")
	sigES := fixture.SignBase(AlgECDSA256, string(input))
	if err := JWS("ES256", ecKey(t), input, sigES); err != nil {
		t.Fatalf("ES256: %v", err)
	}
	sigEd := fixture.SignBase(AlgEd25519, string(input))
	if err := JWS("EdDSA", ed25519Key(t), input, sigEd); err != nil {
		t.Fatalf("EdDSA: %v", err)
	}
	// The dangerous algorithms are rejected by name, before any crypto.
	if err := JWS("none", ed25519Key(t), input, nil); err == nil {
		t.Fatal(`alg "none" must be rejected`)
	}
	err := JWS("HS256", ed25519Key(t), input, nil)
	if err == nil || !strings.Contains(err.Error(), "asymmetric") {
		t.Fatalf("HS256 must be rejected with an explanation: %v", err)
	}
	// Key/alg cross: an ES256 header with an RSA key must not verify.
	if err := JWS("RS256", ecKey(t), input, sigES); err == nil {
		t.Fatal("RS256 with an EC key must be rejected")
	}
}
