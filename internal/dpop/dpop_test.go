// Tests for RFC 9449 DPoP proof verification: signature against the
// embedded key, claim binding (htm/htu/iat/ath/nonce), and the
// key-confusion rejections that make DPoP safe to accept.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
	"github.com/JaydenCJ/httpsigcheck/internal/keys"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
)

const testNow = int64(1783814400) // 2026-07-12T00:00:00Z

func claims(overrides map[string]any) map[string]any {
	c := map[string]any{
		"jti": "unique-id-0001",
		"htm": "POST",
		"htu": "https://server.example.test/token",
		"iat": testNow - 10,
	}
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func expect() Expect {
	return Expect{
		Method: "POST",
		URL:    "https://server.example.test/token",
		Now:    testNow,
		Skew:   30,
		MaxAge: 300,
	}
}

func findCheck(checks []report.Check, name string) (report.Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return report.Check{}, false
}

func TestGenuineES256ProofPasses(t *testing.T) {
	r := Verify(fixture.DPoPProof("ES256", claims(nil), nil), expect())
	if !r.OK() {
		t.Fatalf("genuine proof failed: %+v", r.Checks)
	}
	if r.Alg != "ES256" || r.KeyKind != "ecdsa-p256" {
		t.Fatalf("alg=%s key=%s", r.Alg, r.KeyKind)
	}
	if r.Thumbprint == "" {
		t.Fatal("thumbprint must be computed for genuine proofs")
	}
}

func TestGenuineEdDSAProofPasses(t *testing.T) {
	r := Verify(fixture.DPoPProof("EdDSA", claims(nil), nil), expect())
	if !r.OK() {
		t.Fatalf("genuine EdDSA proof failed: %+v", r.Checks)
	}
}

func TestHeaderRejections(t *testing.T) {
	leakyJWK := fixture.ECJWK()
	leakyJWK["d"] = "AAAA"
	cases := []struct {
		name       string
		override   map[string]any
		checkName  string
		wantDetail string
	}{
		// A plain JWT presented as a proof must be rejected on typ.
		{"wrong typ", map[string]any{"typ": "JWT"}, "typ", "dpop+jwt"},
		// A proof without its public key cannot be verified at all.
		{"missing jwk", map[string]any{"jwk": nil}, "jwk", "must embed"},
		// A client accidentally embedding its private key is a real
		// incident class; the check must call it out as a leak.
		{"private key in jwk", map[string]any{"jwk": leakyJWK}, "jwk", "leak"},
		// alg none: well-formed, correctly typed, still worthless.
		{"alg none", map[string]any{"alg": "none"}, "signature", "none"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proof := fixture.DPoPProof("ES256", claims(nil), c.override)
			r := Verify(proof, expect())
			if r.OK() {
				t.Fatal("broken proof accepted")
			}
			chk, _ := findCheck(r.Checks, c.checkName)
			if chk.Status != report.StatusFail || !strings.Contains(chk.Detail, c.wantDetail) {
				t.Fatalf("%s check = %+v", c.checkName, chk)
			}
		})
	}
}

func TestTamperedClaimsFailTheSignature(t *testing.T) {
	proof := fixture.DPoPProof("ES256", claims(nil), nil)
	parts := strings.Split(proof, ".")
	// Re-encode the claims with a different htu but keep the original
	// signature: a classic token-swap attempt.
	swapped, _ := base64.RawURLEncoding.DecodeString(parts[1])
	altered := strings.Replace(string(swapped), "/token", "/steal", 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(altered))
	r := Verify(strings.Join(parts, "."), expect())
	c, _ := findCheck(r.Checks, "signature")
	if c.Status != report.StatusFail {
		t.Fatalf("signature check = %+v", c)
	}
}

func TestHTMMismatchExplainsCase(t *testing.T) {
	proof := fixture.DPoPProof("ES256", claims(map[string]any{"htm": "post"}), nil)
	r := Verify(proof, expect())
	c, _ := findCheck(r.Checks, "htm")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "case-sensitive") {
		t.Fatalf("htm check = %+v", c)
	}
}

func TestHTUComparison(t *testing.T) {
	// Default port, host case, query, and fragment must not matter.
	proof := fixture.DPoPProof("ES256",
		claims(map[string]any{"htu": "HTTPS://SERVER.example.test:443/token"}), nil)
	e := expect()
	e.URL = "https://server.example.test/token?state=xyz#frag"
	r := Verify(proof, e)
	c, _ := findCheck(r.Checks, "htu")
	if c.Status != report.StatusOK {
		t.Fatalf("htu check = %+v", c)
	}

	// A real mismatch must show both normalized URIs.
	proof = fixture.DPoPProof("ES256", claims(nil), nil)
	e = expect()
	e.URL = "https://other.example.test/token"
	r = Verify(proof, e)
	c, _ = findCheck(r.Checks, "htu")
	if c.Status != report.StatusFail ||
		!strings.Contains(c.Detail, "server.example.test") ||
		!strings.Contains(c.Detail, "other.example.test") {
		t.Fatalf("htu check = %+v", c)
	}
}

func TestIATWindow(t *testing.T) {
	// Too old.
	old := fixture.DPoPProof("ES256", claims(map[string]any{"iat": testNow - 3600}), nil)
	r := Verify(old, expect())
	c, _ := findCheck(r.Checks, "iat")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "old") {
		t.Fatalf("old iat check = %+v", c)
	}
	// From the future.
	future := fixture.DPoPProof("ES256", claims(map[string]any{"iat": testNow + 3600}), nil)
	r = Verify(future, expect())
	c, _ = findCheck(r.Checks, "iat")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "future") {
		t.Fatalf("future iat check = %+v", c)
	}
	// Missing entirely.
	missing := fixture.DPoPProof("ES256", claims(map[string]any{"iat": nil}), nil)
	r = Verify(missing, expect())
	c, _ = findCheck(r.Checks, "iat")
	if c.Status != report.StatusFail {
		t.Fatalf("missing iat check = %+v", c)
	}
	// An exp claim is optional, but when present and past, it kills
	// the proof.
	expired := fixture.DPoPProof("ES256", claims(map[string]any{"exp": testNow - 600}), nil)
	r = Verify(expired, expect())
	c, _ = findCheck(r.Checks, "exp")
	if c.Status != report.StatusFail {
		t.Fatalf("exp check = %+v", c)
	}
}

func TestATHBindsTheAccessToken(t *testing.T) {
	token := "example-access-token-value"
	sum := sha256.Sum256([]byte(token))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])

	proof := fixture.DPoPProof("ES256", claims(map[string]any{"ath": ath}), nil)
	e := expect()
	e.AccessToken = token
	if r := Verify(proof, e); !r.OK() {
		t.Fatalf("matching ath failed: %+v", r.Checks)
	}

	e.AccessToken = "a-different-token"
	r := Verify(proof, e)
	c, _ := findCheck(r.Checks, "ath")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "different token") {
		t.Fatalf("ath mismatch check = %+v", c)
	}

	// RFC 9449 §4.3: at a resource server, the proof must hash the
	// presented token; a proof without ath must not be accepted.
	bare := fixture.DPoPProof("ES256", claims(nil), nil)
	e = expect()
	e.AccessToken = "some-token"
	r = Verify(bare, e)
	c, _ = findCheck(r.Checks, "ath")
	if c.Status != report.StatusFail {
		t.Fatalf("missing ath check = %+v", c)
	}
}

func TestNonceEcho(t *testing.T) {
	e := expect()
	e.Nonce = "server-nonce-123"
	// Proof without a nonce fails when one is expected.
	r := Verify(fixture.DPoPProof("ES256", claims(nil), nil), e)
	c, _ := findCheck(r.Checks, "nonce")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "retry") {
		t.Fatalf("missing nonce check = %+v", c)
	}
	// Matching nonce passes.
	withNonce := fixture.DPoPProof("ES256", claims(map[string]any{"nonce": "server-nonce-123"}), nil)
	if r := Verify(withNonce, e); !r.OK() {
		t.Fatalf("matching nonce failed: %+v", r.Checks)
	}
}

func TestJKTBinding(t *testing.T) {
	tp, err := keys.Thumbprint(fixture.ECJWK())
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	proof := fixture.DPoPProof("ES256", claims(nil), nil)
	e := expect()
	e.JKT = tp
	if r := Verify(proof, e); !r.OK() {
		t.Fatalf("matching jkt failed: %+v", r.Checks)
	}
	e.JKT = "WRONG_THUMBPRINT_VALUE_____________________"
	r := Verify(proof, e)
	c, _ := findCheck(r.Checks, "jkt")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "different key") {
		t.Fatalf("jkt mismatch check = %+v", c)
	}
}

func TestMalformedTokens(t *testing.T) {
	for name, token := range map[string]string{
		"two parts":     "aaaa.bbbb",
		"empty":         "",
		"padded base64": "eyJhbGciOiJFUzI1NiJ9==.e30.c2ln",
		"not json":      base64.RawURLEncoding.EncodeToString([]byte("hi")) + ".e30.c2ln",
	} {
		r := Verify(token, expect())
		if r.OK() {
			t.Errorf("%s: malformed token accepted", name)
		}
		c, ok := findCheck(r.Checks, "format")
		if !ok || c.Status != report.StatusFail {
			t.Errorf("%s: format check = %+v", name, r.Checks)
		}
	}
}

func TestMissingJTIFails(t *testing.T) {
	proof := fixture.DPoPProof("ES256", claims(map[string]any{"jti": nil}), nil)
	r := Verify(proof, expect())
	c, _ := findCheck(r.Checks, "jti")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "replay") {
		t.Fatalf("jti check = %+v", c)
	}
}

func TestUncheckedClaimsAreReportedAsSkips(t *testing.T) {
	// ath and nonce present but nothing to compare against: surfaced
	// as skips so the operator knows checks were not run.
	proof := fixture.DPoPProof("ES256",
		claims(map[string]any{"ath": "AAA", "nonce": "n1"}), nil)
	r := Verify(proof, expect())
	if !r.OK() {
		t.Fatalf("proof should still pass: %+v", r.Checks)
	}
	athCheck, _ := findCheck(r.Checks, "ath")
	nonceCheck, _ := findCheck(r.Checks, "nonce")
	if athCheck.Status != report.StatusSkip || nonceCheck.Status != report.StatusSkip {
		t.Fatalf("ath=%+v nonce=%+v", athCheck, nonceCheck)
	}
}
