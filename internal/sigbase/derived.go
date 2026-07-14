package sigbase

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
)

// derivedValue implements RFC 9421 §2.2: derived components.
func derivedValue(msg *httpmsg.Message, name string, params []sfv.Param, opts Options) ([]string, error) {
	// Only @query-param takes an identifier parameter (;name).
	if name != "@query-param" {
		for _, p := range params {
			return nil, fmt.Errorf("unexpected identifier parameter ;%s", p.Key)
		}
	}

	if name == "@status" {
		if !msg.IsResponse {
			return nil, fmt.Errorf("@status only exists on responses, but the message is a request")
		}
		return []string{strconv.Itoa(msg.StatusCode)}, nil
	}
	if msg.IsResponse {
		return nil, fmt.Errorf("%s only exists on requests, but the message is a response (responses need the ;req parameter to reach into their request, which v0.1.0 does not support)", name)
	}

	tgt, err := parseTarget(msg, opts)
	if err != nil {
		return nil, err
	}

	switch name {
	case "@method":
		return []string{msg.Method}, nil
	case "@request-target":
		return []string{msg.RequestTarget}, nil
	case "@scheme":
		return []string{tgt.scheme}, nil
	case "@authority":
		return []string{tgt.authority}, nil
	case "@target-uri":
		return []string{tgt.uri()}, nil
	case "@path":
		return []string{tgt.path}, nil
	case "@query":
		// Always includes the leading "?"; an absent query string is
		// the bare "?" (RFC 9421 §2.2.7).
		return []string{"?" + tgt.query}, nil
	case "@query-param":
		return queryParamValues(tgt, params)
	default:
		return nil, fmt.Errorf("unknown derived component")
	}
}

// target is the decomposed effective target URI of a request.
type target struct {
	scheme    string
	authority string // normalized: lowercase, default port stripped
	path      string // raw absolute path, never empty
	query     string // raw query, without "?"
	hasQuery  bool
}

func (t target) uri() string {
	u := t.scheme + "://" + t.authority + t.path
	if t.hasQuery {
		u += "?" + t.query
	}
	return u
}

// parseTarget reconstructs the target URI from the request line and the
// Host field, without percent-decoding anything: base lines carry the
// path and query as they appeared on the wire.
func parseTarget(msg *httpmsg.Message, opts Options) (target, error) {
	t := target{scheme: opts.scheme()}
	rt := msg.RequestTarget

	switch {
	case strings.HasPrefix(rt, "/"):
		// origin-form: authority comes from the Host field.
		host, ok := msg.Get("Host")
		if !ok || host == "" {
			return t, fmt.Errorf("request has no Host field, so the authority cannot be derived")
		}
		t.authority = normalizeAuthority(host, t.scheme)
		t.path, t.query, t.hasQuery = splitPathQuery(rt)
	case strings.Contains(rt, "://"):
		// absolute-form: everything is in the request target.
		rest := rt[strings.Index(rt, "://")+3:]
		t.scheme = strings.ToLower(rt[:strings.Index(rt, "://")])
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			if q := strings.IndexByte(rest, '?'); q >= 0 {
				t.authority = normalizeAuthority(rest[:q], t.scheme)
				t.path = "/"
				t.query = rest[q+1:]
				t.hasQuery = true
				return t, nil
			}
			t.authority = normalizeAuthority(rest, t.scheme)
			t.path = "/"
			return t, nil
		}
		t.authority = normalizeAuthority(rest[:slash], t.scheme)
		t.path, t.query, t.hasQuery = splitPathQuery(rest[slash:])
	default:
		return t, fmt.Errorf("request target %q is neither origin-form nor absolute-form; asterisk-form and authority-form have no derived URI components", rt)
	}
	return t, nil
}

func splitPathQuery(pq string) (path, query string, hasQuery bool) {
	if i := strings.IndexByte(pq, '?'); i >= 0 {
		return orRoot(pq[:i]), pq[i+1:], true
	}
	return orRoot(pq), "", false
}

func orRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// normalizeAuthority lowercases the host and strips the scheme's
// default port, per RFC 9110 §4.2.3 URI normalization.
func normalizeAuthority(auth, scheme string) string {
	auth = strings.ToLower(strings.TrimSpace(auth))
	switch scheme {
	case "https":
		auth = strings.TrimSuffix(auth, ":443")
	case "http":
		auth = strings.TrimSuffix(auth, ":80")
	}
	return auth
}

// queryParamValues implements RFC 9421 §2.2.8: parse the query as
// application/x-www-form-urlencoded pairs, select by re-encoded name,
// and emit one base line per occurrence, in order.
func queryParamValues(tgt target, params []sfv.Param) ([]string, error) {
	nameParam, ok := sfv.GetParam(params, "name")
	if !ok {
		return nil, fmt.Errorf("@query-param requires a ;name parameter")
	}
	if nameParam.Type != sfv.TypeString {
		return nil, fmt.Errorf("@query-param ;name must be an sf-string")
	}
	wantName, err := recodeQueryComponent(nameParam.Str)
	if err != nil {
		return nil, fmt.Errorf("invalid ;name value: %v", err)
	}

	var out []string
	var seenNames []string
	for _, pair := range strings.Split(tgt.query, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, err := recodeQueryComponent(rawName)
		if err != nil {
			return nil, fmt.Errorf("query parameter %q does not decode: %v", rawName, err)
		}
		seenNames = append(seenNames, name)
		if name != wantName {
			continue
		}
		value, err := recodeQueryComponent(rawValue)
		if err != nil {
			return nil, fmt.Errorf("query value for %q does not decode: %v", rawName, err)
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no query parameter named %q (re-encoded names present: %s)",
			wantName, strings.Join(seenNames, ", "))
	}
	return out, nil
}

// recodeQueryComponent percent-decodes a form-urlencoded component
// ("+" means space) and re-encodes it strictly: only unreserved
// characters stay literal, everything else becomes uppercase %XX.
// Signer and verifier both normalizing this way is what makes
// @query-param immune to encoding-variation attacks.
func recodeQueryComponent(s string) (string, error) {
	decoded, err := formDecode(s)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if isUnreserved(c) {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String(), nil
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	}
	return false
}

func formDecode(s string) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+':
			sb.WriteByte(' ')
		case '%':
			if i+2 >= len(s) {
				return "", fmt.Errorf("truncated percent escape")
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", fmt.Errorf("bad percent escape %q", s[i:i+3])
			}
			sb.WriteByte(hi<<4 | lo)
			i += 2
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
