// Tests for the RFC 8941 structured-field parser and its canonical
// serializer. The parse→serialize round trip must normalize, because
// RFC 9421 defines the "@signature-params" line as the canonical
// re-serialization of the parsed Signature-Input member.
package sfv

import (
	"bytes"
	"testing"
)

func TestParseDictionarySignatureInputShape(t *testing.T) {
	// A realistic Signature-Input value must come back as an inner
	// list with ordered parameters.
	d, err := ParseDictionary(`sig1=("@method" "@authority" "content-digest");created=1618884473;keyid="test-key-ed25519"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, ok := d.Get("sig1")
	if !ok || !m.IsInner {
		t.Fatalf("sig1 should be an inner list, got %+v", m)
	}
	if len(m.Inner.Items) != 3 {
		t.Fatalf("want 3 covered components, got %d", len(m.Inner.Items))
	}
	if m.Inner.Items[2].Bare.Str != "content-digest" {
		t.Fatalf("third component = %q", m.Inner.Items[2].Bare.Str)
	}
	if len(m.Inner.Params) != 2 || m.Inner.Params[0].Key != "created" || m.Inner.Params[1].Key != "keyid" {
		t.Fatalf("parameter order not preserved: %+v", m.Inner.Params)
	}
	if m.Inner.Params[0].Value.Int != 1618884473 {
		t.Fatalf("created = %d", m.Inner.Params[0].Value.Int)
	}
}

func TestParseDictionaryOmittedValueIsBooleanTrue(t *testing.T) {
	d, err := ParseDictionary(`a, b;x="1", c=5`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	a, _ := d.Get("a")
	if a.IsInner || a.Item.Bare.Type != TypeBool || !a.Item.Bare.Bool {
		t.Fatalf("bare key must mean boolean true, got %+v", a)
	}
	b, _ := d.Get("b")
	if len(b.Item.Params) != 1 || b.Item.Params[0].Key != "x" {
		t.Fatalf("params on omitted value lost: %+v", b)
	}
}

func TestParseDictionaryLastDuplicateKeyWins(t *testing.T) {
	// RFC 8941 §4.2.2: later members replace earlier ones in place.
	d, err := ParseDictionary(`k=1, other=9, k=2`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, _ := d.Get("k")
	if m.Item.Bare.Int != 2 {
		t.Fatalf("want last duplicate to win, got %d", m.Item.Bare.Int)
	}
	if len(d.Entries) != 2 || d.Entries[0].Key != "k" {
		t.Fatalf("duplicate must replace in place: %+v", d.Entries)
	}
}

func TestParseDictionaryRejectsTrailingComma(t *testing.T) {
	if _, err := ParseDictionary(`a=1,`); err == nil {
		t.Fatal("trailing comma must be rejected")
	}
	if _, err := ParseDictionary(`a=1 b=2`); err == nil {
		t.Fatal("missing comma must be rejected")
	}
}

func TestStringEscapingBothWays(t *testing.T) {
	it, err := ParseItem(`"a \"quoted\" \\ backslash"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if it.Bare.Str != `a "quoted" \ backslash` {
		t.Fatalf("got %q", it.Bare.Str)
	}
	// Only \" and \\ are legal escapes.
	if _, err := ParseItem(`"bad \n escape"`); err == nil {
		t.Fatal(`\n must be rejected`)
	}
	if _, err := ParseItem(`"unterminated`); err == nil {
		t.Fatal("unterminated string must be rejected")
	}
	// Serialization mirrors the same two escapes and nothing else.
	got, err := SerializeBare(String(`he said "hi" \o/`))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if got != `"he said \"hi\" \\o/"` {
		t.Fatalf("got %s", got)
	}
	if _, err := SerializeBare(String("newline\n")); err == nil {
		t.Fatal("non-printable characters must be rejected")
	}
}

func TestParseByteSequenceAcceptsUnpaddedBase64(t *testing.T) {
	// Signers in the wild omit padding; both spellings must decode to
	// the same bytes.
	padded, err := ParseItem(`:aGVsbG8=:`)
	if err != nil {
		t.Fatalf("padded: %v", err)
	}
	unpadded, err := ParseItem(`:aGVsbG8:`)
	if err != nil {
		t.Fatalf("unpadded: %v", err)
	}
	if !bytes.Equal(padded.Bare.Bytes, []byte("hello")) || !bytes.Equal(unpadded.Bare.Bytes, []byte("hello")) {
		t.Fatalf("decoded %q / %q", padded.Bare.Bytes, unpadded.Bare.Bytes)
	}
}

func TestNumberLimitsAndDecimalCanonicalization(t *testing.T) {
	if _, err := ParseItem("1234567890123456"); err == nil {
		t.Fatal("16-digit integer must be rejected (max 15)")
	}
	if _, err := ParseItem("1.2345"); err == nil {
		t.Fatal("4 fraction digits must be rejected (max 3)")
	}
	it, err := ParseItem("-42")
	if err != nil || it.Bare.Int != -42 {
		t.Fatalf("negative integer: %v %+v", err, it)
	}
	// "1.500" and "1.5" are the same decimal; serialization must be
	// canonical or base reconstruction diverges from the signer's.
	for input, want := range map[string]string{
		"1.500":  "1.5",
		"2.000":  "2.0",
		"-0.750": "-0.75",
	} {
		it, err := ParseItem(input)
		if err != nil {
			t.Fatalf("%s: %v", input, err)
		}
		got, _ := SerializeBare(it.Bare)
		if got != want {
			t.Errorf("%s serialized to %s, want %s", input, got, want)
		}
	}
}

func TestParseBooleanAndToken(t *testing.T) {
	f, err := ParseItem("?0")
	if err != nil || f.Bare.Type != TypeBool || f.Bare.Bool {
		t.Fatalf("?0: %v %+v", err, f)
	}
	tok, err := ParseItem("sha-256")
	if err != nil || tok.Bare.Type != TypeToken || tok.Bare.Token != "sha-256" {
		t.Fatalf("token: %v %+v", err, tok)
	}
	if _, err := ParseItem("?2"); err == nil {
		t.Fatal("?2 must be rejected")
	}
}

func TestParseInnerListRejectsTrailingGarbage(t *testing.T) {
	if _, err := ParseInnerList(`("@method") extra`); err == nil {
		t.Fatal("trailing garbage must be rejected")
	}
	if _, err := ParseInnerList(`("@method"`); err == nil {
		t.Fatal("unterminated inner list must be rejected")
	}
	if _, err := ParseInnerList(`"@method"`); err == nil {
		t.Fatal("inner list must start with '('")
	}
}

func TestSerializeInnerListIsCanonical(t *testing.T) {
	// Sloppy-but-legal spacing normalizes to the canonical form the
	// signer used when serializing its own @signature-params line.
	il, err := ParseInnerList(`( "@method"   "@path" );created=1618884473;keyid="k"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := SerializeInnerList(il)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want := `("@method" "@path");created=1618884473;keyid="k"`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestSerializeBooleanTrueParamOmitsValue(t *testing.T) {
	it, err := ParseItem(`"content-digest";sf=?1`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	params, err := SerializeParams(it.Params)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if params != ";sf" {
		t.Fatalf("boolean-true param must collapse to bare key, got %q", params)
	}
}

func TestSerializeDictionaryRoundTrip(t *testing.T) {
	d, err := ParseDictionary(`sha-256=:aGVsbG8=:,flag,  x="y"`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := SerializeDictionary(d)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	want := `sha-256=:aGVsbG8=:, flag, x="y"`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
