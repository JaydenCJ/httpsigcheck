// Package sigbase reconstructs the RFC 9421 signature base: the exact
// byte string a signer signed, rebuilt from the message and the covered
// component list. Verification is only ever as good as this
// reconstruction, so every rule of RFC 9421 §2 lives here, and every
// failure names the component that caused it.
package sigbase

import (
	"fmt"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
)

// Options tunes reconstruction for context the message itself cannot
// carry: an HTTP/1.1 request line does not name its scheme.
type Options struct {
	// Scheme is assumed for @scheme, @target-uri, and default-port
	// stripping in @authority. Defaults to "https".
	Scheme string
}

func (o Options) scheme() string {
	if o.Scheme == "" {
		return "https"
	}
	return strings.ToLower(o.Scheme)
}

// Line is one signature base line.
type Line struct {
	Identifier string // serialized component identifier, incl. params
	Value      string
}

// Base is a fully reconstructed signature base.
type Base struct {
	Lines      []Line
	ParamsLine string // serialized covered-components inner list
}

// Text renders the base exactly as it is signed: one line per covered
// component, then the "@signature-params" line, LF-separated with no
// trailing newline (RFC 9421 §2.5).
func (b *Base) Text() string {
	var sb strings.Builder
	for _, l := range b.Lines {
		sb.WriteString(l.Identifier)
		sb.WriteString(": ")
		sb.WriteString(l.Value)
		sb.WriteByte('\n')
	}
	sb.WriteString(`"@signature-params": `)
	sb.WriteString(b.ParamsLine)
	return sb.String()
}

// Build reconstructs the signature base for one signature's covered
// component list against the given message.
func Build(msg *httpmsg.Message, covered sfv.InnerList, opts Options) (*Base, error) {
	base := &Base{}
	seen := map[string]bool{}
	for _, item := range covered.Items {
		if item.Bare.Type != sfv.TypeString {
			got, _ := sfv.SerializeBare(item.Bare)
			return nil, fmt.Errorf("covered component %s: identifiers must be sf-strings, got %s",
				got, item.Bare.Type)
		}
		ident, err := serializeIdentifier(item)
		if err != nil {
			return nil, err
		}
		if seen[ident] {
			return nil, fmt.Errorf("component %s: listed twice in covered components (forbidden by RFC 9421 §2.5)", ident)
		}
		seen[ident] = true

		values, err := componentValues(msg, item, opts)
		if err != nil {
			return nil, fmt.Errorf("component %s: %w", ident, err)
		}
		for _, v := range values {
			base.Lines = append(base.Lines, Line{Identifier: ident, Value: v})
		}
	}
	paramsLine, err := sfv.SerializeInnerList(covered)
	if err != nil {
		return nil, fmt.Errorf("serializing @signature-params: %w", err)
	}
	base.ParamsLine = paramsLine
	return base, nil
}

// serializeIdentifier renders a covered component as it appears on the
// left of a base line: quoted name plus its identifier parameters.
func serializeIdentifier(item sfv.Item) (string, error) {
	name, err := sfv.SerializeBare(item.Bare)
	if err != nil {
		return "", err
	}
	params, err := sfv.SerializeParams(item.Params)
	if err != nil {
		return "", err
	}
	return name + params, nil
}

// componentValues resolves one covered component to its base line
// value(s). Only "@query-param" can legally yield more than one line.
func componentValues(msg *httpmsg.Message, item sfv.Item, opts Options) ([]string, error) {
	name := item.Bare.Str
	if name != strings.ToLower(name) {
		return nil, fmt.Errorf("component names must be lowercase (RFC 9421 §2.1)")
	}
	if name == "@signature-params" {
		return nil, fmt.Errorf("must not appear in its own covered component list")
	}
	if _, ok := sfv.GetParam(item.Params, "req"); ok {
		return nil, fmt.Errorf("the ;req parameter (request-bound response signatures) is not supported in v0.1.0")
	}
	if _, ok := sfv.GetParam(item.Params, "tr"); ok {
		return nil, fmt.Errorf("the ;tr parameter (trailer fields) is not supported in v0.1.0")
	}
	if strings.HasPrefix(name, "@") {
		v, err := derivedValue(msg, name, item.Params, opts)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	v, err := fieldValue(msg, name, item.Params)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// fieldValue implements RFC 9421 §2.1: HTTP field components, including
// the sf, key, and bs parameters.
func fieldValue(msg *httpmsg.Message, name string, params []sfv.Param) (string, error) {
	values := msg.Values(name)
	if values == nil {
		return "", fmt.Errorf("field is not present in the message")
	}

	_, hasSF := sfv.GetParam(params, "sf")
	keyParam, hasKey := sfv.GetParam(params, "key")
	_, hasBS := sfv.GetParam(params, "bs")

	if hasBS && (hasSF || hasKey) {
		return "", fmt.Errorf("the ;bs parameter cannot be combined with ;sf or ;key (RFC 9421 §2.1.3)")
	}

	if hasBS {
		// Each field instance is wrapped as its own byte sequence,
		// then the sequences are joined — this is what makes values
		// with internal commas tamper-evident.
		parts := make([]string, 0, len(values))
		for _, v := range values {
			s, err := sfv.SerializeBare(sfv.Bytes([]byte(v)))
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ", "), nil
	}

	combined := strings.Join(values, ", ")

	if hasKey {
		if keyParam.Type != sfv.TypeString {
			return "", fmt.Errorf("the ;key parameter must be an sf-string")
		}
		dict, err := sfv.ParseDictionary(combined)
		if err != nil {
			return "", fmt.Errorf("field is not a parsable Dictionary (required by ;key): %v", err)
		}
		member, ok := dict.Get(keyParam.Str)
		if !ok {
			var have []string
			for _, e := range dict.Entries {
				have = append(have, e.Key)
			}
			return "", fmt.Errorf("dictionary has no member %q (members present: %s)",
				keyParam.Str, strings.Join(have, ", "))
		}
		return sfv.SerializeMember(member)
	}

	if hasSF {
		return strictSerialize(name, combined)
	}
	return combined, nil
}

// fieldType is a structured-field type from the HTTP field name registry.
type fieldType int

const (
	typeDictionary fieldType = iota
	typeList
	typeItem
)

// sfRegistry maps lowercase field names to their registered structured
// type, for the ;sf parameter (RFC 9421 §2.1.1 requires parsing "according
// to the field's registered type"). Extend here for new fields.
var sfRegistry = map[string]fieldType{
	"accept-ch":           typeList,
	"accept-signature":    typeDictionary,
	"cache-status":        typeList,
	"client-cert":         typeItem,
	"client-cert-chain":   typeList,
	"content-digest":      typeDictionary,
	"priority":            typeDictionary,
	"proxy-status":        typeList,
	"repr-digest":         typeDictionary,
	"signature":           typeDictionary,
	"signature-input":     typeDictionary,
	"want-content-digest": typeDictionary,
	"want-repr-digest":    typeDictionary,
}

// strictSerialize re-serializes a structured field canonically, per the
// field's registered type.
func strictSerialize(name, combined string) (string, error) {
	ft, ok := sfRegistry[name]
	if !ok {
		return "", fmt.Errorf("the ;sf parameter needs the field's structured type, and %q is not in the built-in registry (known: Dictionary/List/Item fields from the HTTP field name registry); extend sfRegistry in internal/sigbase", name)
	}
	switch ft {
	case typeDictionary:
		d, err := sfv.ParseDictionary(combined)
		if err != nil {
			return "", fmt.Errorf("field does not parse as a Dictionary: %v", err)
		}
		return sfv.SerializeDictionary(d)
	case typeList:
		l, err := sfv.ParseList(combined)
		if err != nil {
			return "", fmt.Errorf("field does not parse as a List: %v", err)
		}
		return sfv.SerializeList(l)
	default:
		it, err := sfv.ParseItem(combined)
		if err != nil {
			return "", fmt.Errorf("field does not parse as an Item: %v", err)
		}
		return sfv.SerializeItem(it)
	}
}
