// Package digest checks RFC 9530 Content-Digest fields against the
// actual message body. A signature that covers content-digest only
// pins the body if the digest itself is correct, so this check is what
// extends signature integrity to the payload.
package digest

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
)

// Result is the outcome for one digest entry.
type Result struct {
	Alg    string `json:"alg"`
	Status string `json:"status"` // "ok", "mismatch", "unsupported", "malformed"
	Detail string `json:"detail"`
}

// Check verifies every entry of every Content-Digest field in the
// message against the body bytes. It returns nil when the message has
// no Content-Digest field.
func Check(msg *httpmsg.Message) []Result {
	values := msg.Values("Content-Digest")
	if values == nil {
		return nil
	}
	dict, err := sfv.ParseDictionary(joinValues(values))
	if err != nil {
		return []Result{{Alg: "content-digest", Status: "malformed",
			Detail: fmt.Sprintf("field does not parse as a Dictionary: %v", err)}}
	}
	if len(dict.Entries) == 0 {
		return []Result{{Alg: "content-digest", Status: "malformed",
			Detail: "field is present but empty"}}
	}

	var out []Result
	for _, e := range dict.Entries {
		out = append(out, checkEntry(e, msg.Body))
	}
	return out
}

func joinValues(values []string) string {
	s := values[0]
	for _, v := range values[1:] {
		s += ", " + v
	}
	return s
}

func checkEntry(e sfv.DictEntry, body []byte) Result {
	r := Result{Alg: e.Key}
	if e.Value.IsInner || e.Value.Item.Bare.Type != sfv.TypeBytes {
		r.Status = "malformed"
		r.Detail = "digest value must be a byte sequence (:base64:)"
		return r
	}
	claimed := e.Value.Item.Bare.Bytes

	var computed []byte
	switch e.Key {
	case "sha-256":
		sum := sha256.Sum256(body)
		computed = sum[:]
	case "sha-512":
		sum := sha512.Sum512(body)
		computed = sum[:]
	default:
		// Registered-but-deprecated (md5, sha, ...) and unknown
		// algorithms are surfaced, not silently trusted.
		r.Status = "unsupported"
		r.Detail = fmt.Sprintf("algorithm %q is not checked (only sha-256 and sha-512 are)", e.Key)
		return r
	}

	if len(claimed) != len(computed) {
		r.Status = "mismatch"
		r.Detail = fmt.Sprintf("claimed digest is %d bytes but %s produces %d", len(claimed), e.Key, len(computed))
		return r
	}
	if subtle.ConstantTimeCompare(claimed, computed) != 1 {
		r.Status = "mismatch"
		r.Detail = fmt.Sprintf("body (%d bytes) hashes to a different value — the content was modified after signing", len(body))
		return r
	}
	r.Status = "ok"
	r.Detail = fmt.Sprintf("matches the body (%d bytes)", len(body))
	return r
}
