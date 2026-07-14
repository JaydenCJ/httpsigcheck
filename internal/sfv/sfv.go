// Package sfv parses and serializes the subset of RFC 8941 Structured
// Field Values that HTTP Message Signatures depend on: Dictionaries,
// Lists, Inner Lists, Items, and Parameters.
//
// Serialization is always canonical (RFC 8941 §4.1). That matters here:
// RFC 9421 defines the "@signature-params" base line as the *canonical
// re-serialization* of the parsed Signature-Input member, so parse →
// serialize must be a normalizing round trip, not a byte copy.
package sfv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ItemType discriminates the bare item variants of RFC 8941 §3.3.
type ItemType int

const (
	TypeInteger ItemType = iota
	TypeDecimal
	TypeString
	TypeToken
	TypeBytes
	TypeBool
)

func (t ItemType) String() string {
	switch t {
	case TypeInteger:
		return "integer"
	case TypeDecimal:
		return "decimal"
	case TypeString:
		return "string"
	case TypeToken:
		return "token"
	case TypeBytes:
		return "byte sequence"
	case TypeBool:
		return "boolean"
	}
	return "unknown"
}

// BareItem is one RFC 8941 bare item. Exactly one field (per Type) is
// meaningful. Decimals keep their canonical text form so round trips
// never lose precision.
type BareItem struct {
	Type    ItemType
	Int     int64
	Decimal string
	Str     string
	Token   string
	Bytes   []byte
	Bool    bool
}

// Param is a single key/value parameter. Order is significant, so
// parameters are kept as a slice, never a map.
type Param struct {
	Key   string
	Value BareItem
}

// Item is a bare item plus its parameters.
type Item struct {
	Bare   BareItem
	Params []Param
}

// InnerList is a parenthesized list of items plus its parameters.
type InnerList struct {
	Items  []Item
	Params []Param
}

// Member is a Dictionary or List member value: either an Item or an
// InnerList (IsInner selects which).
type Member struct {
	IsInner bool
	Item    Item
	Inner   InnerList
}

// DictEntry is one Dictionary member; order is preserved.
type DictEntry struct {
	Key   string
	Value Member
}

// Dictionary is an ordered RFC 8941 Dictionary.
type Dictionary struct {
	Entries []DictEntry
}

// Get returns the entry for key. Later duplicates already replaced
// earlier ones at parse time, per RFC 8941 §4.2.2.
func (d *Dictionary) Get(key string) (Member, bool) {
	for _, e := range d.Entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return Member{}, false
}

// GetParam returns the parameter named key, preserving absence.
func GetParam(params []Param, key string) (BareItem, bool) {
	for _, p := range params {
		if p.Key == key {
			return p.Value, true
		}
	}
	return BareItem{}, false
}

// String constructs a string bare item.
func String(s string) BareItem { return BareItem{Type: TypeString, Str: s} }

// Integer constructs an integer bare item.
func Integer(i int64) BareItem { return BareItem{Type: TypeInteger, Int: i} }

// Bytes constructs a byte-sequence bare item.
func Bytes(b []byte) BareItem { return BareItem{Type: TypeBytes, Bytes: b} }

// Bool constructs a boolean bare item.
func Bool(b bool) BareItem { return BareItem{Type: TypeBool, Bool: b} }

// Token constructs a token bare item.
func Token(t string) BareItem { return BareItem{Type: TypeToken, Token: t} }

// parser is a cursor over the input string.
type parser struct {
	s   string
	pos int
}

func (p *parser) eof() bool     { return p.pos >= len(p.s) }
func (p *parser) peek() byte    { return p.s[p.pos] }
func (p *parser) advance() byte { c := p.s[p.pos]; p.pos++; return c }

func (p *parser) skipSP() {
	for !p.eof() && p.peek() == ' ' {
		p.pos++
	}
}

func (p *parser) skipOWS() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("structured field: %s at offset %d in %q",
		fmt.Sprintf(format, args...), p.pos, p.s)
}

// ParseDictionary parses an RFC 8941 Dictionary (§4.2.2).
func ParseDictionary(s string) (*Dictionary, error) {
	p := &parser{s: strings.Trim(s, " \t")}
	d := &Dictionary{}
	if p.eof() {
		return d, nil
	}
	for {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var m Member
		if !p.eof() && p.peek() == '=' {
			p.advance()
			m, err = p.parseMember()
			if err != nil {
				return nil, err
			}
		} else {
			// Omitted value: boolean true with parameters (§3.2).
			params, err := p.parseParams()
			if err != nil {
				return nil, err
			}
			m = Member{Item: Item{Bare: Bool(true), Params: params}}
		}
		// Duplicate keys: the last instance wins (§4.2.2 step 5.4).
		replaced := false
		for i := range d.Entries {
			if d.Entries[i].Key == key {
				d.Entries[i].Value = m
				replaced = true
				break
			}
		}
		if !replaced {
			d.Entries = append(d.Entries, DictEntry{Key: key, Value: m})
		}
		p.skipOWS()
		if p.eof() {
			return d, nil
		}
		if p.advance() != ',' {
			return nil, p.errf("expected ',' between dictionary members")
		}
		p.skipOWS()
		if p.eof() {
			return nil, p.errf("trailing comma in dictionary")
		}
	}
}

// ParseList parses an RFC 8941 List (§4.2.1).
func ParseList(s string) ([]Member, error) {
	p := &parser{s: strings.Trim(s, " \t")}
	var out []Member
	if p.eof() {
		return out, nil
	}
	for {
		m, err := p.parseMember()
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		p.skipOWS()
		if p.eof() {
			return out, nil
		}
		if p.advance() != ',' {
			return nil, p.errf("expected ',' between list members")
		}
		p.skipOWS()
		if p.eof() {
			return nil, p.errf("trailing comma in list")
		}
	}
}

// ParseItem parses a complete RFC 8941 Item (§4.2.3), requiring the
// whole input to be consumed.
func ParseItem(s string) (Item, error) {
	p := &parser{s: strings.Trim(s, " \t")}
	it, err := p.parseItem()
	if err != nil {
		return Item{}, err
	}
	if !p.eof() {
		return Item{}, p.errf("unexpected trailing characters after item")
	}
	return it, nil
}

// ParseInnerList parses a standalone inner list such as the covered
// components value of Signature-Input, requiring full consumption.
func ParseInnerList(s string) (InnerList, error) {
	p := &parser{s: strings.Trim(s, " \t")}
	if p.eof() || p.peek() != '(' {
		return InnerList{}, errors.New("structured field: inner list must start with '('")
	}
	il, err := p.parseInnerList()
	if err != nil {
		return InnerList{}, err
	}
	if !p.eof() {
		return InnerList{}, p.errf("unexpected trailing characters after inner list")
	}
	return il, nil
}

func (p *parser) parseMember() (Member, error) {
	if !p.eof() && p.peek() == '(' {
		il, err := p.parseInnerList()
		if err != nil {
			return Member{}, err
		}
		return Member{IsInner: true, Inner: il}, nil
	}
	it, err := p.parseItem()
	if err != nil {
		return Member{}, err
	}
	return Member{Item: it}, nil
}

func (p *parser) parseInnerList() (InnerList, error) {
	var il InnerList
	p.advance() // consume '('
	for {
		p.skipSP()
		if p.eof() {
			return il, p.errf("unterminated inner list")
		}
		if p.peek() == ')' {
			p.advance()
			params, err := p.parseParams()
			if err != nil {
				return il, err
			}
			il.Params = params
			return il, nil
		}
		it, err := p.parseItem()
		if err != nil {
			return il, err
		}
		il.Items = append(il.Items, it)
		if !p.eof() && p.peek() != ' ' && p.peek() != ')' {
			return il, p.errf("inner list items must be separated by spaces")
		}
	}
}

func (p *parser) parseItem() (Item, error) {
	bare, err := p.parseBare()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParams()
	if err != nil {
		return Item{}, err
	}
	return Item{Bare: bare, Params: params}, nil
}

func (p *parser) parseParams() ([]Param, error) {
	var params []Param
	for !p.eof() && p.peek() == ';' {
		p.advance()
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		val := Bool(true)
		if !p.eof() && p.peek() == '=' {
			p.advance()
			val, err = p.parseBare()
			if err != nil {
				return nil, err
			}
		}
		// Duplicate parameter keys: last wins (§4.2.3.2 step 2.4).
		replaced := false
		for i := range params {
			if params[i].Key == key {
				params[i].Value = val
				replaced = true
				break
			}
		}
		if !replaced {
			params = append(params, Param{Key: key, Value: val})
		}
	}
	return params, nil
}

func isKeyStart(c byte) bool { return (c >= 'a' && c <= 'z') || c == '*' }

func isKeyChar(c byte) bool {
	return isKeyStart(c) || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
}

func (p *parser) parseKey() (string, error) {
	if p.eof() || !isKeyStart(p.peek()) {
		return "", p.errf("key must start with lowercase letter or '*'")
	}
	start := p.pos
	for !p.eof() && isKeyChar(p.peek()) {
		p.pos++
	}
	return p.s[start:p.pos], nil
}

func (p *parser) parseBare() (BareItem, error) {
	if p.eof() {
		return BareItem{}, p.errf("expected a bare item")
	}
	switch c := p.peek(); {
	case c == '"':
		return p.parseString()
	case c == ':':
		return p.parseBytes()
	case c == '?':
		return p.parseBool()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '*':
		return p.parseToken()
	default:
		return BareItem{}, p.errf("unrecognized bare item start %q", string(c))
	}
}

func (p *parser) parseString() (BareItem, error) {
	p.advance() // consume '"'
	var b strings.Builder
	for {
		if p.eof() {
			return BareItem{}, p.errf("unterminated string")
		}
		c := p.advance()
		switch {
		case c == '\\':
			if p.eof() {
				return BareItem{}, p.errf("dangling backslash in string")
			}
			e := p.advance()
			if e != '"' && e != '\\' {
				return BareItem{}, p.errf("invalid string escape \\%s", string(e))
			}
			b.WriteByte(e)
		case c == '"':
			return String(b.String()), nil
		case c < 0x20 || c > 0x7e:
			return BareItem{}, p.errf("non-printable byte 0x%02x in string", c)
		default:
			b.WriteByte(c)
		}
	}
}

func (p *parser) parseBytes() (BareItem, error) {
	p.advance() // consume ':'
	start := p.pos
	for !p.eof() && p.peek() != ':' {
		p.pos++
	}
	if p.eof() {
		return BareItem{}, p.errf("unterminated byte sequence")
	}
	enc := p.s[start:p.pos]
	p.advance() // consume closing ':'
	// Padding SHOULD be present but parsers are encouraged to accept
	// its absence (§4.2.7); real-world signers do omit it.
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(enc)
		if err != nil {
			return BareItem{}, p.errf("invalid base64 in byte sequence: %v", err)
		}
	}
	return Bytes(raw), nil
}

func (p *parser) parseBool() (BareItem, error) {
	p.advance() // consume '?'
	if p.eof() {
		return BareItem{}, p.errf("truncated boolean")
	}
	switch p.advance() {
	case '0':
		return Bool(false), nil
	case '1':
		return Bool(true), nil
	default:
		return BareItem{}, p.errf("boolean must be ?0 or ?1")
	}
}

func (p *parser) parseNumber() (BareItem, error) {
	start := p.pos
	if p.peek() == '-' {
		p.advance()
	}
	digits := 0
	for !p.eof() && p.peek() >= '0' && p.peek() <= '9' {
		p.advance()
		digits++
	}
	if digits == 0 {
		return BareItem{}, p.errf("number requires at least one digit")
	}
	if p.eof() || p.peek() != '.' {
		if digits > 15 {
			return BareItem{}, p.errf("integer exceeds 15 digits")
		}
		n, err := strconv.ParseInt(p.s[start:p.pos], 10, 64)
		if err != nil {
			return BareItem{}, p.errf("integer out of range: %v", err)
		}
		return Integer(n), nil
	}
	if digits > 12 {
		return BareItem{}, p.errf("decimal integer part exceeds 12 digits")
	}
	intPart := p.s[start:p.pos]
	p.advance() // consume '.'
	fracStart := p.pos
	for !p.eof() && p.peek() >= '0' && p.peek() <= '9' {
		p.advance()
	}
	frac := p.s[fracStart:p.pos]
	if len(frac) == 0 || len(frac) > 3 {
		return BareItem{}, p.errf("decimal fraction must have 1-3 digits")
	}
	return BareItem{Type: TypeDecimal, Decimal: canonDecimal(intPart, frac)}, nil
}

// canonDecimal normalizes a decimal to its canonical serialization:
// trailing fraction zeros dropped, at least one fraction digit kept.
func canonDecimal(intPart, frac string) string {
	frac = strings.TrimRight(frac, "0")
	if frac == "" {
		frac = "0"
	}
	return intPart + "." + frac
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~:/", c) >= 0
}

func (p *parser) parseToken() (BareItem, error) {
	start := p.pos
	p.advance()
	for !p.eof() && isTokenChar(p.peek()) {
		p.pos++
	}
	return Token(p.s[start:p.pos]), nil
}
