// Tests for RFC 9530 Content-Digest checking against real body bytes.
package digest

import (
	"strings"
	"testing"

	"github.com/JaydenCJ/httpsigcheck/internal/fixture"
	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
)

func msgWithDigest(t *testing.T, digestValue, body string) *httpmsg.Message {
	t.Helper()
	raw := "POST /u HTTP/1.1\nHost: a.test\nContent-Digest: " + digestValue + "\n\n" + body
	m, err := httpmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("fixture message: %v", err)
	}
	return m
}

func TestSupportedAlgorithmsMatch(t *testing.T) {
	// sha-256 and sha-512 over a JSON body, and — legal and common on
	// GET requests — a digest over zero bytes.
	cases := []struct {
		name, alg, body string
	}{
		{"sha-256", "sha-256", `{"hello":"world"}`},
		{"sha-512", "sha-512", "payload bytes"},
		{"empty body", "sha-256", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := msgWithDigest(t, fixture.ContentDigest(c.alg, []byte(c.body)), c.body)
			res := Check(m)
			if len(res) != 1 || res[0].Status != "ok" || res[0].Alg != c.alg {
				t.Fatalf("results = %+v", res)
			}
		})
	}
}

func TestTamperedBodyIsExplained(t *testing.T) {
	// Digest computed for one body, message carries another: the
	// mismatch text must say the content changed, with the byte count.
	m := msgWithDigest(t, fixture.ContentDigest("sha-256", []byte("original")), "tampered!")
	res := Check(m)
	if len(res) != 1 || res[0].Status != "mismatch" {
		t.Fatalf("results = %+v", res)
	}
	if !strings.Contains(res[0].Detail, "modified") || !strings.Contains(res[0].Detail, "9 bytes") {
		t.Fatalf("detail should explain the tamper: %q", res[0].Detail)
	}
}

func TestUnknownAlgorithmAndMalformedValueAreSurfaced(t *testing.T) {
	m := msgWithDigest(t, "md5=:AAAA:", "body")
	res := Check(m)
	if len(res) != 1 || res[0].Status != "unsupported" {
		t.Fatalf("unknown alg results = %+v", res)
	}
	m = msgWithDigest(t, `sha-256="not-a-byte-sequence"`, "body")
	res = Check(m)
	if len(res) != 1 || res[0].Status != "malformed" {
		t.Fatalf("malformed results = %+v", res)
	}
}

func TestMultipleEntriesCheckedIndependently(t *testing.T) {
	body := "shared body"
	value := fixture.ContentDigest("sha-256", []byte(body)) + ", " + fixture.ContentDigest("sha-512", []byte("different"))
	m := msgWithDigest(t, value, body)
	res := Check(m)
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %+v", res)
	}
	if res[0].Status != "ok" || res[1].Status != "mismatch" {
		t.Fatalf("statuses = %s / %s", res[0].Status, res[1].Status)
	}
}

func TestNoContentDigestHeaderMeansNoResults(t *testing.T) {
	m, err := httpmsg.Parse([]byte("GET / HTTP/1.1\nHost: a.test\n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res := Check(m); res != nil {
		t.Fatalf("expected nil, got %+v", res)
	}
}
