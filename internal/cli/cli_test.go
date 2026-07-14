// In-process integration tests for the CLI: Run(argv) with fabricated
// message, key, and proof files in temp dirs. Exit codes and output
// text are part of the contract — scripts grep both.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
)

const testNow = int64(1783814400) // 2026-07-12T00:00:00Z

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func signedRequestFile(t *testing.T) string {
	t.Helper()
	body := `{"amount":10,"currency":"EUR"}`
	raw := "POST /payments HTTP/1.1\nHost: api.example.test\nContent-Type: application/json\n" +
		"Content-Digest: " + fixture.ContentDigest("sha-256", []byte(body)) + "\n\n" + body
	covered := `("@method" "@authority" "@path" "content-digest");created=` +
		strconv.FormatInt(testNow, 10) + `;keyid="payments-key-1"`
	return writeFile(t, "request.http", fixture.SignMessage(raw, "sig1", covered, "ed25519"))
}

func ed25519KeyFile(t *testing.T) string {
	t.Helper()
	return writeFile(t, "pub.pem", fixture.Ed25519PublicPEM())
}

func now() string { return strconv.FormatInt(testNow, 10) }

func TestVersionAndHelp(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != ExitOK || out != "httpsigcheck 0.1.0\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, out, _ = run(t, "help")
	if code != ExitOK {
		t.Fatalf("help exit=%d", code)
	}
	for _, cmd := range []string{"verify", "base", "dpop", "version"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("help missing %q", cmd)
		}
	}
}

func TestVerifyGenuineRequestPasses(t *testing.T) {
	code, out, _ := run(t, "verify", "--key", ed25519KeyFile(t), "--now", now(), signedRequestFile(t))
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	for _, want := range []string{
		"verify: PASS (1 of 1 signature valid)",
		`signature "sig1"`,
		`| "@method": POST`, // the base must be visible
		"sha-256",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestVerifyJSONEnvelope(t *testing.T) {
	code, out, _ := run(t, "verify", "--format", "json", "--key", ed25519KeyFile(t), "--now", now(), signedRequestFile(t))
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	var doc struct {
		Tool          string `json:"tool"`
		SchemaVersion int    `json:"schema_version"`
		OK            bool   `json:"ok"`
		Signatures    []struct {
			Label string `json:"label"`
			Alg   string `json:"alg"`
			Base  string `json:"base"`
			OK    bool   `json:"ok"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Tool != "httpsigcheck" || doc.SchemaVersion != 1 || !doc.OK {
		t.Fatalf("envelope = %+v", doc)
	}
	if len(doc.Signatures) != 1 || doc.Signatures[0].Alg != "ed25519" || doc.Signatures[0].Base == "" {
		t.Fatalf("signatures = %+v", doc.Signatures)
	}
}

func TestVerifyTamperedBodyFailsAndExplains(t *testing.T) {
	raw, err := os.ReadFile(signedRequestFile(t))
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"amount":10`, `"amount":99`, 1)
	path := writeFile(t, "tampered.http", tampered)
	code, out, _ := run(t, "verify", "--key", ed25519KeyFile(t), "--now", now(), path)
	if code != ExitFail {
		t.Fatalf("exit=%d, want %d\n%s", code, ExitFail, out)
	}
	// The verdict must not contradict the checks: the signature IS
	// valid, so the verdict line has to say what actually failed.
	if !strings.Contains(out, "verify: FAIL (1 of 1 signature valid, but a content-digest check failed)") ||
		!strings.Contains(out, "content was modified") {
		t.Fatalf("failure not explained:\n%s", out)
	}
}

func TestVerifyWithSharedSecret(t *testing.T) {
	raw := "GET /internal HTTP/1.1\nHost: svc.example.test\n\n"
	covered := `("@method" "@authority");created=` + now()
	path := writeFile(t, "hmac.http", fixture.SignMessage(raw, "sig1", covered, "hmac-sha256"))
	code, out, _ := run(t, "verify", "--secret", fixture.HMACSecret, "--now", now(), path)
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	code, _, _ = run(t, "verify", "--secret", "wrong", "--now", now(), path)
	if code != ExitFail {
		t.Fatalf("wrong secret exit=%d, want %d", code, ExitFail)
	}
}

func TestVerifyLabelFlagSelectsSignature(t *testing.T) {
	raw := "GET /multi HTTP/1.1\nHost: api.example.test\n\n"
	signed := fixture.SignMessage(raw, "alpha", `("@method");created=`+now(), "ed25519")
	signed = fixture.SignMessage(signed, "beta", `("@authority");created=`+now(), "ed25519")
	path := writeFile(t, "multi.http", signed)
	code, out, _ := run(t, "verify", "--key", ed25519KeyFile(t), "--now", now(), "--label", "beta", path)
	if code != ExitOK || strings.Contains(out, `signature "alpha"`) {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, `signature "beta"`) {
		t.Fatalf("beta missing:\n%s", out)
	}
}

func TestBasePrintsExactSignatureBase(t *testing.T) {
	code, out, _ := run(t, "base", signedRequestFile(t))
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	if !strings.HasPrefix(out, `"@method": POST`+"\n") {
		t.Fatalf("base output starts wrong:\n%s", out)
	}
	if !strings.Contains(out, `"@signature-params": ("@method" "@authority" "@path" "content-digest");created=`) {
		t.Fatalf("params line missing:\n%s", out)
	}
}

func TestBaseWithAdHocComponents(t *testing.T) {
	path := writeFile(t, "plain.http", "GET /status?probe=1 HTTP/1.1\nHost: api.example.test\n\n")
	code, out, _ := run(t, "base", "--components", `("@method" "@query")`, path)
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	want := "\"@method\": GET\n\"@query\": ?probe=1\n\"@signature-params\": (\"@method\" \"@query\")\n"
	if out != want {
		t.Fatalf("got:\n%q\nwant:\n%q", out, want)
	}
	// Without --components and without Signature-Input there is no
	// base to print; the error must point at the flag.
	code, _, errOut := run(t, "base", path)
	if code != ExitFail || !strings.Contains(errOut, "--components") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestDPoPGenuineProofPasses(t *testing.T) {
	proof := fixture.DPoPProof("ES256", map[string]any{
		"jti": "id-1", "htm": "POST", "htu": "https://as.example.test/token", "iat": testNow - 5,
	}, nil)
	path := writeFile(t, "proof.jwt", proof)
	code, out, _ := run(t, "dpop", "--method", "POST", "--url", "https://as.example.test/token",
		"--now", now(), path)
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "dpop: PASS") || !strings.Contains(out, "key thumbprint") {
		t.Fatalf("output:\n%s", out)
	}
	// The same proof presented for a different URL must fail with
	// exit code 1.
	code, out, _ = run(t, "dpop", "--method", "POST", "--url", "https://evil.example.test/token",
		"--now", now(), path)
	if code != ExitFail || !strings.Contains(out, "dpop: FAIL") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
}

func TestDPoPAcceptsPastedHeaderLine(t *testing.T) {
	proof := fixture.DPoPProof("ES256", map[string]any{
		"jti": "id-1", "htm": "GET", "htu": "https://rs.example.test/data", "iat": testNow,
	}, nil)
	path := writeFile(t, "header.txt", "DPoP: "+proof+"\n")
	code, _, _ := run(t, "dpop", "--method", "GET", "--url", "https://rs.example.test/data",
		"--now", now(), path)
	if code != ExitOK {
		t.Fatalf("exit=%d", code)
	}
}

func TestDPoPJSONOutput(t *testing.T) {
	proof := fixture.DPoPProof("EdDSA", map[string]any{
		"jti": "id-2", "htm": "GET", "htu": "https://rs.example.test/x", "iat": testNow,
	}, nil)
	path := writeFile(t, "proof.jwt", proof)
	code, out, _ := run(t, "dpop", "--format", "json", "--now", now(), path)
	if code != ExitOK {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	var doc struct {
		Alg        string `json:"alg"`
		Thumbprint string `json:"thumbprint"`
		OK         bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Alg != "EdDSA" || doc.Thumbprint == "" || !doc.OK {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	cases := [][]string{
		{"frobnicate"},
		{"verify"},                                     // no key, no file
		{"verify", "--key", "k.pem"},                   // no file
		{"verify", "--format", "yaml", "x"},            // bad format
		{"verify", "--key", "a", "--secret", "b", "x"}, // both key sources
		{"dpop", "--now", "not-a-time", "x"},
		{},
	}
	for _, args := range cases {
		if code, _, _ := run(t, args...); code != ExitUsage {
			t.Errorf("args %v: exit=%d, want %d", args, code, ExitUsage)
		}
	}
}

func TestMissingFilesExitThree(t *testing.T) {
	code, _, errOut := run(t, "verify", "--key", ed25519KeyFile(t), "/does/not/exist.http")
	if code != ExitRuntime || errOut == "" {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
	code, _, _ = run(t, "verify", "--key", "/does/not/exist.pem", signedRequestFile(t))
	if code != ExitRuntime {
		t.Fatalf("missing key exit=%d", code)
	}
}
