// Tests for raw HTTP message parsing. The parser must preserve exactly
// what signature verification depends on: field order, duplicate
// fields, and untouched body bytes.
package httpmsg

import (
	"bytes"
	"testing"
)

func TestParseRequestLine(t *testing.T) {
	m, err := Parse([]byte("POST /foo?bar=baz HTTP/1.1\nHost: example.test\n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.IsResponse {
		t.Fatal("classified as response")
	}
	if m.Method != "POST" || m.RequestTarget != "/foo?bar=baz" || m.Proto != "HTTP/1.1" {
		t.Fatalf("start line parsed as %q %q %q", m.Method, m.RequestTarget, m.Proto)
	}
	// Files are saved with LF, wire captures with CRLF: the head
	// section must parse identically either way.
	crlf, err := Parse([]byte("POST /foo?bar=baz HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	if err != nil {
		t.Fatalf("CRLF parse: %v", err)
	}
	if crlf.Method != m.Method || crlf.RequestTarget != m.RequestTarget {
		t.Fatal("LF and CRLF messages parsed differently")
	}
}

func TestParseResponseStatusLine(t *testing.T) {
	m, err := Parse([]byte("HTTP/1.1 503 Service Unavailable\nRetry-After: 10\n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !m.IsResponse || m.StatusCode != 503 {
		t.Fatalf("got response=%v status=%d", m.IsResponse, m.StatusCode)
	}
}

func TestBodyBytesAreVerbatim(t *testing.T) {
	// Content-Digest is computed over these exact bytes, so the parser
	// must not normalize line endings or strip anything in the body.
	body := "line1\r\nline2\n\nend"
	m, err := Parse([]byte("POST /u HTTP/1.1\nHost: a.test\n\n" + body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(m.Body, []byte(body)) {
		t.Fatalf("body altered: %q", m.Body)
	}
}

func TestObsFoldContinuationJoinsWithSingleSpace(t *testing.T) {
	m, err := Parse([]byte("GET / HTTP/1.1\nHost: a.test\nX-Long: first part\n    second part\n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	v, _ := m.Get("X-Long")
	if v != "first part second part" {
		t.Fatalf("obs-fold joined as %q", v)
	}
}

func TestDuplicateFieldsKeepOrder(t *testing.T) {
	m, err := Parse([]byte("GET / HTTP/1.1\nHost: a.test\nX-Multi: one\nOther: x\nX-Multi: two\n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := m.Values("x-multi") // lookup is case-insensitive
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("duplicate field values = %v", got)
	}
	// Leading/trailing whitespace around values is trimmed, per the
	// field-value rules the signature base builder relies on.
	m, err = Parse([]byte("GET / HTTP/1.1\nHost:   spaced.test  \n\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v, _ := m.Get("Host"); v != "spaced.test" {
		t.Fatalf("value not trimmed: %q", v)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"one-word line":    "GARBAGE\n\n",
		"bad proto":        "GET / JUNK/1.1\n\n",
		"header no colon":  "GET / HTTP/1.1\nBadHeader\n\n",
		"space in name":    "GET / HTTP/1.1\nBad Header: x\n\n",
		"bad status code":  "HTTP/1.1 9999 Nope\n\n",
		"leading obs-fold": "GET / HTTP/1.1\n folded: x\n\n",
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
}
