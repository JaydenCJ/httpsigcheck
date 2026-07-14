// Known-answer tests for signature base reconstruction. The expected
// strings are hand-derived from the rules in RFC 9421 §2 — they anchor
// the verifier independently of its own code, so a bug in Build cannot
// hide behind a matching bug in a test helper.
package sigbase

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
)

func mustMsg(t *testing.T, raw string) *httpmsg.Message {
	t.Helper()
	m, err := httpmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("fixture message: %v", err)
	}
	return m
}

func build(t *testing.T, raw, covered string) (*Base, error) {
	t.Helper()
	il, err := sfv.ParseInnerList(covered)
	if err != nil {
		t.Fatalf("fixture covered list: %v", err)
	}
	return Build(mustMsg(t, raw), il, Options{})
}

func mustBuild(t *testing.T, raw, covered string) *Base {
	t.Helper()
	b, err := build(t, raw, covered)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return b
}

const postReq = "POST /foo?bar=baz HTTP/1.1\nHost: example.test\nContent-Type: application/json\n\n{\"hello\":\"world\"}"

func TestBaseMinimalRequestKnownAnswer(t *testing.T) {
	b := mustBuild(t, postReq, `("@method" "@authority" "@path" "content-type");created=1618884473;keyid="test-key"`)
	want := `"@method": POST
"@authority": example.test
"@path": /foo
"content-type": application/json
"@signature-params": ("@method" "@authority" "@path" "content-type");created=1618884473;keyid="test-key"`
	if b.Text() != want {
		t.Fatalf("base mismatch:\n--- got ---\n%s\n--- want ---\n%s", b.Text(), want)
	}
	// The signed bytes end exactly at the @signature-params line; a
	// trailing newline would break every signature.
	if strings.HasSuffix(b.Text(), "\n") {
		t.Fatal("base text must not end with a newline")
	}
}

func TestBaseDerivedComponentKnownAnswers(t *testing.T) {
	// Each case: one message, one covered list, the exact expected
	// line values, hand-derived from RFC 9421 §2.2.
	cases := []struct {
		name    string
		raw     string
		covered string
		scheme  string
		want    []string
	}{
		{
			name:    "query present",
			raw:     postReq,
			covered: `("@query")`,
			want:    []string{"?bar=baz"},
		},
		{
			name: "query absent is bare question mark",
			raw:  "GET /just-path HTTP/1.1\nHost: a.test\n\n",
			// RFC 9421 §2.2.7: an absent query string is "?".
			covered: `("@query")`,
			want:    []string{"?"},
		},
		{
			name:    "request-target, target-uri, scheme",
			raw:     postReq,
			covered: `("@request-target" "@target-uri" "@scheme")`,
			want:    []string{"/foo?bar=baz", "https://example.test/foo?bar=baz", "https"},
		},
		{
			name:    "authority lowercases and strips default port",
			raw:     "GET / HTTP/1.1\nHost: EXAMPLE.test:443\n\n",
			covered: `("@authority")`,
			want:    []string{"example.test"},
		},
		{
			name:    "authority keeps a non-default port",
			raw:     "GET / HTTP/1.1\nHost: example.test:8443\n\n",
			covered: `("@authority")`,
			want:    []string{"example.test:8443"},
		},
		{
			name:    "scheme option drives http default port",
			raw:     "GET /x HTTP/1.1\nHost: example.test:80\n\n",
			covered: `("@scheme" "@authority" "@target-uri")`,
			scheme:  "http",
			want:    []string{"http", "example.test", "http://example.test/x"},
		},
		{
			name:    "absolute-form target overrides Host and scheme",
			raw:     "GET http://Origin.test:80/pets?limit=2 HTTP/1.1\nHost: ignored.test\n\n",
			covered: `("@scheme" "@authority" "@path" "@query")`,
			want:    []string{"http", "origin.test", "/pets", "?limit=2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			il, err := sfv.ParseInnerList(c.covered)
			if err != nil {
				t.Fatalf("covered list: %v", err)
			}
			b, err := Build(mustMsg(t, c.raw), il, Options{Scheme: c.scheme})
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			for i, w := range c.want {
				if b.Lines[i].Value != w {
					t.Errorf("line %d = %q, want %q", i, b.Lines[i].Value, w)
				}
			}
		})
	}
}

func TestBaseQueryParamReencodingAndRepeats(t *testing.T) {
	// Values decode per form-urlencoded rules and re-encode strictly,
	// so "+" and "%2F" spellings cannot be used to smuggle changes.
	raw := "GET /path?q=hello+world&slash=a%2Fb HTTP/1.1\nHost: a.test\n\n"
	b := mustBuild(t, raw, `("@query-param";name="q" "@query-param";name="slash")`)
	if b.Lines[0].Identifier != `"@query-param";name="q"` {
		t.Fatalf("identifier = %q", b.Lines[0].Identifier)
	}
	if b.Lines[0].Value != "hello%20world" || b.Lines[1].Value != "a%2Fb" {
		t.Fatalf("values = %q, %q", b.Lines[0].Value, b.Lines[1].Value)
	}

	// RFC 9421 §2.2.8: every occurrence of a repeated name gets its own
	// base line, in order — the one place an identifier legally repeats.
	raw = "GET /find?tag=a&other=x&tag=b HTTP/1.1\nHost: a.test\n\n"
	b = mustBuild(t, raw, `("@query-param";name="tag")`)
	if len(b.Lines) != 2 || b.Lines[0].Value != "a" || b.Lines[1].Value != "b" {
		t.Fatalf("repeated param lines = %+v", b.Lines)
	}
	if b.Lines[0].Identifier != b.Lines[1].Identifier {
		t.Fatal("both lines must carry the same identifier")
	}
}

func TestBaseFieldMultipleInstancesJoinWithCommaSpace(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: a.test\nX-Custom: one\nX-Custom: two\n\n"
	b := mustBuild(t, raw, `("x-custom")`)
	if b.Lines[0].Value != "one, two" {
		t.Fatalf("joined field = %q", b.Lines[0].Value)
	}
}

func TestBaseFieldKeyParamExtractsDictionaryMember(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: a.test\nExample-Dict: a=1, b=2;x=1;y=2, c=(a b c)\n\n"
	b := mustBuild(t, raw, `("example-dict";key="b")`)
	if b.Lines[0].Value != "2;x=1;y=2" {
		t.Fatalf(";key member = %q", b.Lines[0].Value)
	}
	b = mustBuild(t, raw, `("example-dict";key="c")`)
	if b.Lines[0].Value != "(a b c)" {
		t.Fatalf(";key inner-list member = %q", b.Lines[0].Value)
	}
	_, err := build(t, raw, `("example-dict";key="zz")`)
	if err == nil || !strings.Contains(err.Error(), `no member "zz"`) {
		t.Fatalf("missing member should be named: %v", err)
	}
}

func TestBaseFieldSfParamCanonicalizes(t *testing.T) {
	// Sloppy spacing in a structured field normalizes under ;sf, so
	// verifier and signer agree even after proxies reflow the value.
	raw := "GET / HTTP/1.1\nHost: a.test\nContent-Digest:   sha-256=:aGVsbG8=:  ,  x=1\n\n"
	b := mustBuild(t, raw, `("content-digest";sf)`)
	if b.Lines[0].Value != "sha-256=:aGVsbG8=:, x=1" {
		t.Fatalf(";sf value = %q", b.Lines[0].Value)
	}
}

func TestBaseFieldBsParamWrapsRawBytes(t *testing.T) {
	raw := "GET / HTTP/1.1\nHost: a.test\nX-Custom: value one\nX-Custom: value two\n\n"
	b := mustBuild(t, raw, `("x-custom";bs)`)
	// base64("value one") and base64("value two"), each its own byte
	// sequence — commas inside values can no longer collide with the
	// ", " join.
	if b.Lines[0].Value != ":dmFsdWUgb25l:, :dmFsdWUgdHdv:" {
		t.Fatalf(";bs value = %q", b.Lines[0].Value)
	}
}

func TestBaseStatusComponent(t *testing.T) {
	if _, err := build(t, postReq, `("@status")`); err == nil {
		t.Fatal("@status on a request must fail")
	}
	resp := "HTTP/1.1 200 OK\nDate: Tue, 20 Apr 2021 02:07:56 GMT\n\n"
	b := mustBuild(t, resp, `("@status" "date")`)
	if b.Lines[0].Value != "200" {
		t.Fatalf("@status = %q", b.Lines[0].Value)
	}
	// And the reverse: request-only components fail on responses.
	if _, err := build(t, resp, `("@method")`); err == nil {
		t.Fatal("@method on a response must fail")
	}
}

func TestBaseErrorsAreSpecificAndActionable(t *testing.T) {
	// Every reconstruction failure must name the component and say
	// what to do — these strings surface verbatim in the CLI.
	cases := []struct {
		name    string
		raw     string
		covered string
		wantErr string
	}{
		{
			name:    "missing field",
			raw:     postReq,
			covered: `("authorization")`,
			wantErr: "not present",
		},
		{
			name:    "duplicate component",
			raw:     postReq,
			covered: `("@method" "@method")`,
			wantErr: "twice",
		},
		{
			name:    "uppercase component name",
			raw:     postReq,
			covered: `("Content-Type")`,
			wantErr: "lowercase",
		},
		{
			name:    "signature-params cannot cover itself",
			raw:     postReq,
			covered: `("@signature-params")`,
			wantErr: "own covered component list",
		},
		{
			name:    "req parameter is version-scoped",
			raw:     "HTTP/1.1 200 OK\nDate: x\n\n",
			covered: `("@method";req)`,
			wantErr: "not supported in v0.1.0",
		},
		{
			name:    "missing Host for authority",
			raw:     "GET / HTTP/1.1\nX-Other: v\n\n",
			covered: `("@authority")`,
			wantErr: "Host",
		},
		{
			name:    "sf on a field outside the registry",
			raw:     "GET / HTTP/1.1\nHost: a.test\nX-Mystery: a=1\n\n",
			covered: `("x-mystery";sf)`,
			wantErr: "registry",
		},
		{
			name:    "bs cannot combine with sf",
			raw:     "GET / HTTP/1.1\nHost: a.test\nContent-Digest: sha-256=:aGVsbG8=:\n\n",
			covered: `("content-digest";bs;sf)`,
			wantErr: "cannot be combined",
		},
		{
			name:    "missing query param lists candidates",
			raw:     "GET /find?alpha=1&beta=2 HTTP/1.1\nHost: a.test\n\n",
			covered: `("@query-param";name="gamma")`,
			wantErr: "alpha, beta",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := build(t, c.raw, c.covered)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not contain %q", err, c.wantErr)
			}
		})
	}
}

func TestExtractParamsTypesEnforced(t *testing.T) {
	il, _ := sfv.ParseInnerList(`("@method");created=1618884473;expires=1618884773;alg="ed25519";keyid="k";nonce="n";tag="t"`)
	p, err := ExtractParams(il)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if *p.Created != 1618884473 || *p.Expires != 1618884773 {
		t.Fatalf("timestamps: %+v", p)
	}
	if p.Alg != "ed25519" || p.KeyID != "k" || p.Nonce != "n" || p.Tag != "t" {
		t.Fatalf("strings: %+v", p)
	}
	// created as a string is a type violation, not a value to coerce.
	il, _ = sfv.ParseInnerList(`("@method");created="soon"`)
	if _, err := ExtractParams(il); err == nil {
		t.Fatal("created must be an integer")
	}
}

func TestExtractParamsSurfacesUnknownKeys(t *testing.T) {
	il, _ := sfv.ParseInnerList(`("@method");created=1;custom="x"`)
	p, err := ExtractParams(il)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(p.Unknown) != 1 || p.Unknown[0] != "custom" {
		t.Fatalf("unknown params = %v", p.Unknown)
	}
}
