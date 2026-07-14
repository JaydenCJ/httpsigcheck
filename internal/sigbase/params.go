package sigbase

import (
	"fmt"

	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
)

// SigParams are the signature parameters of one Signature-Input member
// (RFC 9421 §2.3). Pointers distinguish "absent" from zero values.
type SigParams struct {
	Created *int64
	Expires *int64
	Alg     string
	KeyID   string
	Nonce   string
	Tag     string
	// Unknown lists parameter keys outside the registry, surfaced so
	// the report can flag them (they are still signed, being part of
	// the serialized @signature-params line).
	Unknown []string
}

// ExtractParams reads and type-checks the signature parameters from a
// covered-components inner list.
func ExtractParams(il sfv.InnerList) (SigParams, error) {
	var sp SigParams
	for _, p := range il.Params {
		switch p.Key {
		case "created", "expires":
			if p.Value.Type != sfv.TypeInteger {
				return sp, fmt.Errorf("signature parameter %q must be an integer, got %s", p.Key, p.Value.Type)
			}
			v := p.Value.Int
			if p.Key == "created" {
				sp.Created = &v
			} else {
				sp.Expires = &v
			}
		case "alg", "keyid", "nonce", "tag":
			if p.Value.Type != sfv.TypeString {
				return sp, fmt.Errorf("signature parameter %q must be an sf-string, got %s", p.Key, p.Value.Type)
			}
			switch p.Key {
			case "alg":
				sp.Alg = p.Value.Str
			case "keyid":
				sp.KeyID = p.Value.Str
			case "nonce":
				sp.Nonce = p.Value.Str
			case "tag":
				sp.Tag = p.Value.Str
			}
		default:
			sp.Unknown = append(sp.Unknown, p.Key)
		}
	}
	return sp, nil
}
