package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// SerializeBare renders a bare item in canonical RFC 8941 §4.1 form.
func SerializeBare(b BareItem) (string, error) {
	switch b.Type {
	case TypeInteger:
		return strconv.FormatInt(b.Int, 10), nil
	case TypeDecimal:
		return b.Decimal, nil
	case TypeString:
		var sb strings.Builder
		sb.WriteByte('"')
		for i := 0; i < len(b.Str); i++ {
			c := b.Str[i]
			if c < 0x20 || c > 0x7e {
				return "", fmt.Errorf("string contains non-printable byte 0x%02x", c)
			}
			if c == '"' || c == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('"')
		return sb.String(), nil
	case TypeToken:
		return b.Token, nil
	case TypeBytes:
		return ":" + base64.StdEncoding.EncodeToString(b.Bytes) + ":", nil
	case TypeBool:
		if b.Bool {
			return "?1", nil
		}
		return "?0", nil
	}
	return "", fmt.Errorf("unknown bare item type %d", b.Type)
}

// SerializeParams renders parameters (leading ';', no spaces —
// canonical form per §4.1.1.2). Boolean-true values are omitted.
func SerializeParams(params []Param) (string, error) {
	var sb strings.Builder
	for _, p := range params {
		sb.WriteByte(';')
		sb.WriteString(p.Key)
		if p.Value.Type == TypeBool && p.Value.Bool {
			continue
		}
		v, err := SerializeBare(p.Value)
		if err != nil {
			return "", err
		}
		sb.WriteByte('=')
		sb.WriteString(v)
	}
	return sb.String(), nil
}

// SerializeItem renders an item with its parameters.
func SerializeItem(it Item) (string, error) {
	bare, err := SerializeBare(it.Bare)
	if err != nil {
		return "", err
	}
	params, err := SerializeParams(it.Params)
	if err != nil {
		return "", err
	}
	return bare + params, nil
}

// SerializeInnerList renders an inner list with its parameters, e.g.
// `("@method" "@path");created=1618884473;keyid="k"`. This exact form is
// the "@signature-params" base line value in RFC 9421 §2.5.
func SerializeInnerList(il InnerList) (string, error) {
	var sb strings.Builder
	sb.WriteByte('(')
	for i, it := range il.Items {
		if i > 0 {
			sb.WriteByte(' ')
		}
		s, err := SerializeItem(it)
		if err != nil {
			return "", err
		}
		sb.WriteString(s)
	}
	sb.WriteByte(')')
	params, err := SerializeParams(il.Params)
	if err != nil {
		return "", err
	}
	sb.WriteString(params)
	return sb.String(), nil
}

// SerializeMember renders a Dictionary or List member value.
func SerializeMember(m Member) (string, error) {
	if m.IsInner {
		return SerializeInnerList(m.Inner)
	}
	return SerializeItem(m.Item)
}

// SerializeDictionary renders a Dictionary in canonical form
// (", " between members; boolean-true values collapse to bare keys).
func SerializeDictionary(d *Dictionary) (string, error) {
	var parts []string
	for _, e := range d.Entries {
		if !e.Value.IsInner && e.Value.Item.Bare.Type == TypeBool && e.Value.Item.Bare.Bool {
			params, err := SerializeParams(e.Value.Item.Params)
			if err != nil {
				return "", err
			}
			parts = append(parts, e.Key+params)
			continue
		}
		v, err := SerializeMember(e.Value)
		if err != nil {
			return "", err
		}
		parts = append(parts, e.Key+"="+v)
	}
	return strings.Join(parts, ", "), nil
}

// SerializeList renders a List in canonical form.
func SerializeList(members []Member) (string, error) {
	var parts []string
	for _, m := range members {
		v, err := SerializeMember(m)
		if err != nil {
			return "", err
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", "), nil
}
