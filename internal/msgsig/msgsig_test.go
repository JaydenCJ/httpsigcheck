// Tests for the RFC 9421 verification pipeline: fixture-signed
// messages go through the full check sequence, and every failure mode
// must produce the named check and the explanation the CLI shows.
package msgsig

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/keys"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
)

const testNow = int64(1783814400) // 2026-07-12T00:00:00Z

func unsignedReq(body string) string {
	raw := "POST /payments?limit=2 HTTP/1.1\nHost: api.example.test\nContent-Type: application/json\n"
	if body != "" {
		raw += "Content-Digest: " + fixture.ContentDigest("sha-256", []byte(body)) + "\n"
	}
	return raw + "\n" + body
}

func signedReq(t *testing.T, alg string) string {
	t.Helper()
	covered := `("@method" "@authority" "@path" "content-digest");created=` + fmtInt(testNow) + `;keyid="test-key"`
	return fixture.SignMessage(unsignedReq(`{"amount":10}`), "sig1", covered, alg)
}

func fmtInt(n int64) string { return strconv.FormatInt(n, 10) }

func ed25519Key(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.LoadPublic([]byte(fixture.Ed25519PublicPEM()))
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return k
}

func parse(t *testing.T, raw string) *httpmsg.Message {
	t.Helper()
	m, err := httpmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func opts() Options {
	return Options{Now: testNow, Skew: 30}
}

func findCheck(checks []report.Check, name string) (report.Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return report.Check{}, false
}

func TestVerifyGenuineEd25519MessagePasses(t *testing.T) {
	r := Verify(parse(t, signedReq(t, "ed25519")), ed25519Key(t), opts())
	if !r.OK() {
		t.Fatalf("genuine message failed: %+v", r)
	}
	if len(r.Signatures) != 1 || r.Signatures[0].Label != "sig1" {
		t.Fatalf("signatures = %+v", r.Signatures)
	}
	sig, _ := findCheck(r.Signatures[0].Checks, "signature")
	if sig.Status != report.StatusOK {
		t.Fatalf("signature check = %+v", sig)
	}
	if r.Signatures[0].Alg != "ed25519" {
		t.Fatalf("alg = %q", r.Signatures[0].Alg)
	}
}

func TestVerifyExposesTheSignatureBase(t *testing.T) {
	// Showing the base is the whole point of the tool: it must be
	// present and contain the covered component lines.
	r := Verify(parse(t, signedReq(t, "ed25519")), ed25519Key(t), opts())
	base := r.Signatures[0].Base
	if base == nil {
		t.Fatal("base missing from result")
	}
	if !strings.Contains(base.Text(), `"@method": POST`) ||
		!strings.Contains(base.Text(), `"@signature-params": `) {
		t.Fatalf("base text incomplete:\n%s", base.Text())
	}
}

func TestVerifyWrongEd25519KeyFails(t *testing.T) {
	// Same algorithm, different key: the base is fine, the crypto is
	// not — exactly what verifying with the wrong key looks like.
	other := ed25519.NewKeyFromSeed([]byte("a-completely-different-seed-32b!"))
	der, err := x509.MarshalPKIXPublicKey(other.Public())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	wrongKey, err := keys.LoadPublic(pemKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := Verify(parse(t, signedReq(t, "ed25519")), wrongKey, opts())
	if r.OK() {
		t.Fatal("wrong key accepted")
	}
	sig, _ := findCheck(r.Signatures[0].Checks, "signature")
	if sig.Status != report.StatusFail {
		t.Fatalf("signature check = %+v", sig)
	}

	// Tampered covered component, right key: same failing check, and
	// the failure must tell the user what to do next — with the base
	// intact so a base mismatch can be ruled out.
	tampered := strings.Replace(signedReq(t, "ed25519"), "/payments", "/refunds", 1)
	r = Verify(parse(t, tampered), ed25519Key(t), opts())
	if r.OK() {
		t.Fatal("tampered path accepted")
	}
	sig, _ = findCheck(r.Signatures[0].Checks, "signature")
	if sig.Status != report.StatusFail || !strings.Contains(sig.Detail, "compare the base") {
		t.Fatalf("signature failure should tell the user what to do next: %+v", sig)
	}
	baseCheck, _ := findCheck(r.Signatures[0].Checks, "base")
	if baseCheck.Status != report.StatusOK {
		t.Fatalf("base reconstruction should still succeed: %+v", baseCheck)
	}
}

func TestVerifyTamperedBodyFailsViaContentDigest(t *testing.T) {
	raw := signedReq(t, "ed25519")
	tampered := strings.Replace(raw, `{"amount":10}`, `{"amount":99}`, 1)
	r := Verify(parse(t, tampered), ed25519Key(t), opts())
	if r.OK() {
		t.Fatal("tampered body accepted")
	}
	// The signature itself still verifies (it covers the digest field,
	// not the body); the digest check is what catches the swap.
	sig, _ := findCheck(r.Signatures[0].Checks, "signature")
	if sig.Status != report.StatusOK {
		t.Fatalf("signature over headers should still verify: %+v", sig)
	}
	if len(r.Digests) != 1 || r.Digests[0].Status != "mismatch" {
		t.Fatalf("digest results = %+v", r.Digests)
	}
}

func TestVerifyHMACWithSharedSecret(t *testing.T) {
	raw := signedReq(t, "hmac-sha256")
	key, _ := keys.Shared(fixture.HMACSecret)
	r := Verify(parse(t, raw), key, opts())
	if !r.OK() {
		t.Fatalf("hmac message failed: %+v", r.Signatures[0].Checks)
	}
	wrong, _ := keys.Shared("not-the-secret")
	if Verify(parse(t, raw), wrong, opts()).OK() {
		t.Fatal("wrong shared secret accepted")
	}
}

func TestVerifyRSAPSSAndV15(t *testing.T) {
	rsaKey, err := keys.LoadPublic([]byte(fixture.RSAPublicPEM))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := Verify(parse(t, signedReq(t, "rsa-pss-sha512")), rsaKey, opts())
	if !r.OK() {
		t.Fatalf("rsa-pss message failed: %+v", r.Signatures[0].Checks)
	}
	// v1.5 needs --alg because the key alone is ambiguous.
	o := opts()
	o.Alg = "rsa-v1_5-sha256"
	r = Verify(parse(t, signedReq(t, "rsa-v1_5-sha256")), rsaKey, o)
	if !r.OK() {
		t.Fatalf("rsa-v1_5 message failed: %+v", r.Signatures[0].Checks)
	}
}

func TestVerifyParameterMismatchesAreHardFailures(t *testing.T) {
	// alg="hmac-sha256" in the message plus an Ed25519 key must fail
	// closed: the alg parameter is attacker-controlled.
	covered := `("@method");created=` + fmtInt(testNow) + `;alg="hmac-sha256"`
	raw := fixture.SignMessage(unsignedReq(""), "sig1", covered, "ed25519")
	r := Verify(parse(t, raw), ed25519Key(t), opts())
	if r.OK() {
		t.Fatal("alg/key confusion accepted")
	}
	alg, _ := findCheck(r.Signatures[0].Checks, "alg")
	if alg.Status != report.StatusFail || !strings.Contains(alg.Detail, "requires") {
		t.Fatalf("alg check = %+v", alg)
	}

	// keyid naming a different key than the one supplied is the
	// "verifying with the wrong key" case, called out by name.
	covered = `("@method");created=` + fmtInt(testNow) + `;keyid="key-A"`
	raw = fixture.SignMessage(unsignedReq(""), "sig1", covered, "ed25519")
	key := ed25519Key(t)
	key.KeyID = "key-B"
	r = Verify(parse(t, raw), key, opts())
	kid, _ := findCheck(r.Signatures[0].Checks, "keyid")
	if kid.Status != report.StatusFail || !strings.Contains(kid.Detail, "wrong key") {
		t.Fatalf("keyid check = %+v", kid)
	}
}

func TestVerifyTimeWindow(t *testing.T) {
	// created in the future: clock-sync problem, must fail with a hint.
	covered := `("@method");created=` + fmtInt(testNow+3600)
	raw := fixture.SignMessage(unsignedReq(""), "sig1", covered, "ed25519")
	r := Verify(parse(t, raw), ed25519Key(t), opts())
	created, _ := findCheck(r.Signatures[0].Checks, "created")
	if created.Status != report.StatusFail || !strings.Contains(created.Detail, "future") {
		t.Fatalf("created check = %+v", created)
	}

	// expires in the past: hard failure regardless of other checks.
	covered = `("@method");created=` + fmtInt(testNow-7200) + `;expires=` + fmtInt(testNow-3600)
	raw = fixture.SignMessage(unsignedReq(""), "sig1", covered, "ed25519")
	r = Verify(parse(t, raw), ed25519Key(t), opts())
	if r.OK() {
		t.Fatal("expired signature accepted")
	}
	exp, _ := findCheck(r.Signatures[0].Checks, "expires")
	if exp.Status != report.StatusFail || !strings.Contains(exp.Detail, "expired") {
		t.Fatalf("expires check = %+v", exp)
	}

	// --max-age is opt-in staleness for signatures without expires.
	covered = `("@method");created=` + fmtInt(testNow-900)
	raw = fixture.SignMessage(unsignedReq(""), "sig1", covered, "ed25519")
	o := opts()
	o.MaxAge = 300
	r = Verify(parse(t, raw), ed25519Key(t), o)
	created, _ = findCheck(r.Signatures[0].Checks, "created")
	if created.Status != report.StatusFail || !strings.Contains(created.Detail, "max-age") {
		t.Fatalf("created check = %+v", created)
	}
	// Without --max-age the same message is fine.
	if !Verify(parse(t, raw), ed25519Key(t), opts()).OK() {
		t.Fatal("message should pass without a max-age limit")
	}
}

func TestVerifyMessageLevelFailuresExplain(t *testing.T) {
	// No Signature-Input at all.
	r := Verify(parse(t, unsignedReq("")), ed25519Key(t), opts())
	if r.OK() {
		t.Fatal("unsigned message must not pass")
	}
	c, ok := findCheck(r.Checks, "signature-input")
	if !ok || !strings.Contains(c.Detail, "nothing to verify") {
		t.Fatalf("message-level check = %+v", r.Checks)
	}

	// Signature-Input without the Signature field carrying the bytes.
	raw := strings.Replace(unsignedReq(""), "\n\n",
		"\nSignature-Input: sig1=(\"@method\");created="+fmtInt(testNow)+"\n\n", 1)
	r = Verify(parse(t, raw), ed25519Key(t), opts())
	c, _ = findCheck(r.Checks, "signature")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "no Signature field") {
		t.Fatalf("check = %+v", r.Checks)
	}
}

func TestVerifyLabelSelection(t *testing.T) {
	// Two signatures; verifying only the selected label.
	covered := `("@method");created=` + fmtInt(testNow)
	raw := fixture.SignMessage(unsignedReq(""), "first", covered, "ed25519")
	raw = fixture.SignMessage(raw, "second", `("@authority");created=`+fmtInt(testNow), "ed25519")
	o := opts()
	o.Labels = []string{"second"}
	r := Verify(parse(t, raw), ed25519Key(t), o)
	if len(r.Signatures) != 1 || r.Signatures[0].Label != "second" {
		t.Fatalf("selected signatures = %+v", r.Signatures)
	}
	// A label that does not exist must name the ones that do.
	o.Labels = []string{"ghost"}
	r = Verify(parse(t, raw), ed25519Key(t), o)
	c, _ := findCheck(r.Checks, "label")
	if c.Status != report.StatusFail || !strings.Contains(c.Detail, "first") {
		t.Fatalf("label check = %+v", c)
	}
	// And without a label filter, every signature is verified.
	r = Verify(parse(t, raw), ed25519Key(t), opts())
	if len(r.Signatures) != 2 || !r.OK() {
		t.Fatalf("want both signatures verified and passing, got %d, ok=%v",
			len(r.Signatures), r.OK())
	}
}

func TestVerifyCoverageDiagnostics(t *testing.T) {
	// Signature valid but body not covered: verdict stays PASS, and
	// the body check warns loudly.
	covered := `("@method");created=` + fmtInt(testNow)
	raw := fixture.SignMessage("POST /u HTTP/1.1\nHost: a.test\n\nsome body", "sig1", covered, "ed25519")
	r := Verify(parse(t, raw), ed25519Key(t), opts())
	if !r.OK() {
		t.Fatalf("valid signature should pass: %+v", r.Signatures[0].Checks)
	}
	body, _ := findCheck(r.Signatures[0].Checks, "body")
	if body.Status != report.StatusSkip || !strings.Contains(body.Detail, "NOT protected") {
		t.Fatalf("body check = %+v", body)
	}

	// Signature-Input covers a field the message no longer has — the
	// classic "proxy stripped my header" case: the base failure must
	// name the missing component.
	covered = `("@method" "x-request-id");created=` + fmtInt(testNow)
	raw = fixture.SignMessage(
		"POST /u HTTP/1.1\nHost: a.test\nX-Request-Id: abc\n\n", "sig1", covered, "ed25519")
	stripped := strings.Replace(raw, "X-Request-Id: abc\n", "", 1)
	r = Verify(parse(t, stripped), ed25519Key(t), opts())
	base, _ := findCheck(r.Signatures[0].Checks, "base")
	if base.Status != report.StatusFail || !strings.Contains(base.Detail, "x-request-id") {
		t.Fatalf("base check = %+v", base)
	}
}
