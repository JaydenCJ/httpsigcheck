// Package dpop verifies RFC 9449 DPoP proof JWTs offline: JWS signature
// against the embedded key, and every claim an authorization or resource
// server is required to check. Each rule is a named check with a
// human-readable explanation, because "invalid_dpop_proof" alone helps
// nobody.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/keys"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
	"github.com/JaydenCJ/httpsigcheck/internal/verify"
)

// Expect carries the request-side facts the proof must match.
type Expect struct {
	Method      string // expected htm; empty skips the check
	URL         string // expected htu; empty skips the check
	AccessToken string // when set, ath must match its SHA-256
	JKT         string // when set, the key thumbprint must match (cnf.jkt binding)
	Nonce       string // when set, the nonce claim must match
	Now         int64  // verification time (unix seconds)
	Skew        int64  // tolerated clock skew, seconds
	MaxAge      int64  // maximum accepted proof age, seconds
}

// Result is the full outcome of verifying one proof.
type Result struct {
	Checks     []report.Check
	Alg        string
	Thumbprint string // RFC 7638 thumbprint of the embedded key
	KeyKind    string
	HeaderJSON string // re-indented decoded header, for display
	ClaimsJSON string // re-indented decoded claims, for display
}

// OK reports whether no check failed.
func (r *Result) OK() bool { return report.AllOK(r.Checks) }

func (r *Result) ok(name, detail string) {
	r.Checks = append(r.Checks, report.Check{Name: name, Status: report.StatusOK, Detail: detail})
}

func (r *Result) fail(name, detail string) {
	r.Checks = append(r.Checks, report.Check{Name: name, Status: report.StatusFail, Detail: detail})
}

func (r *Result) skip(name, detail string) {
	r.Checks = append(r.Checks, report.Check{Name: name, Status: report.StatusSkip, Detail: detail})
}

// Verify checks one compact-serialization DPoP proof. It always returns
// a Result; structural failures simply end the check list early.
func Verify(token string, exp Expect) *Result {
	r := &Result{}

	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		r.fail("format", fmt.Sprintf("a DPoP proof is a compact JWS with 3 dot-separated parts, got %d", len(parts)))
		return r
	}
	header, ok := decodeJSONPart(r, "header", parts[0])
	if !ok {
		return r
	}
	claims, ok := decodeJSONPart(r, "claims", parts[1])
	if !ok {
		return r
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		r.fail("format", fmt.Sprintf("signature part is not unpadded base64url: %v", err))
		return r
	}
	r.ok("format", "compact JWS, all three parts decode")
	r.HeaderJSON = indentJSON(header)
	r.ClaimsJSON = indentJSON(claims)

	checkTyp(r, header)
	key := checkHeaderKey(r, header)
	if key != nil {
		signingInput := []byte(parts[0] + "." + parts[1])
		if err := verify.JWS(r.Alg, key, signingInput, sig); err != nil {
			r.fail("signature", err.Error()+" — the proof was not produced by the embedded key, or was altered in transit")
		} else {
			r.ok("signature", fmt.Sprintf("%s signature verifies with the embedded %s key", r.Alg, key.Kind))
		}
	}

	checkJTI(r, claims)
	checkHTM(r, claims, exp)
	checkHTU(r, claims, exp)
	checkTimes(r, claims, exp)
	checkNonce(r, claims, exp)
	checkATH(r, claims, exp)
	checkJKT(r, exp)
	return r
}

func decodeJSONPart(r *Result, name, part string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil {
		r.fail("format", fmt.Sprintf("%s part is not unpadded base64url: %v", name, err))
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		r.fail("format", fmt.Sprintf("%s part is not a JSON object: %v", name, err))
		return nil, false
	}
	return m, true
}

func checkTyp(r *Result, header map[string]any) {
	typ, _ := header["typ"].(string)
	if typ != "dpop+jwt" {
		r.fail("typ", fmt.Sprintf(`header typ must be "dpop+jwt", got %q — a plain JWT presented as a proof is rejected by design`, typ))
		return
	}
	r.ok("typ", `header typ is "dpop+jwt"`)
}

// checkHeaderKey validates alg and the embedded jwk, returning the
// parsed key when usable.
func checkHeaderKey(r *Result, header map[string]any) *keys.Key {
	alg, _ := header["alg"].(string)
	r.Alg = alg

	jwkAny, present := header["jwk"]
	if !present {
		r.fail("jwk", "header has no jwk member; a DPoP proof must embed its public key")
		return nil
	}
	jwkMap, isObj := jwkAny.(map[string]any)
	if !isObj {
		r.fail("jwk", "header jwk member is not a JSON object")
		return nil
	}
	if keys.HasPrivateMaterial(jwkMap) {
		r.fail("jwk", "embedded jwk carries private or symmetric key material (d/p/q/k), which RFC 9449 §4.2 forbids — the client just leaked its key")
		return nil
	}
	key, err := keys.ParseJWKMap(jwkMap)
	if err != nil {
		r.fail("jwk", fmt.Sprintf("embedded jwk does not parse: %v", err))
		return nil
	}
	if tp, err := keys.Thumbprint(jwkMap); err == nil {
		r.Thumbprint = tp
	}
	r.KeyKind = key.Kind
	r.ok("jwk", fmt.Sprintf("embedded public key is %s (thumbprint %s)", key.Kind, r.Thumbprint))
	return key
}

func checkJTI(r *Result, claims map[string]any) {
	jti, _ := claims["jti"].(string)
	if jti == "" {
		r.fail("jti", "claims have no jti (unique identifier); servers cannot detect proof replay without it")
		return
	}
	r.ok("jti", fmt.Sprintf("present (%d chars); replay detection is the server's job — check your jti cache", len(jti)))
}

func checkHTM(r *Result, claims map[string]any, exp Expect) {
	htm, _ := claims["htm"].(string)
	if htm == "" {
		r.fail("htm", "claims have no htm (HTTP method) member")
		return
	}
	if exp.Method == "" {
		r.skip("htm", fmt.Sprintf("proof says %s; pass --method to check it", htm))
		return
	}
	if htm != exp.Method {
		hint := ""
		if strings.EqualFold(htm, exp.Method) {
			hint = " (differs only by case — HTTP methods are case-sensitive)"
		}
		r.fail("htm", fmt.Sprintf("proof was bound to %s but the request is %s%s", htm, exp.Method, hint))
		return
	}
	r.ok("htm", fmt.Sprintf("bound to %s", htm))
}

func checkHTU(r *Result, claims map[string]any, exp Expect) {
	htu, _ := claims["htu"].(string)
	if htu == "" {
		r.fail("htu", "claims have no htu (HTTP URI) member")
		return
	}
	if exp.URL == "" {
		r.skip("htu", fmt.Sprintf("proof says %s; pass --url to check it", htu))
		return
	}
	got, err := normalizeHTU(htu)
	if err != nil {
		r.fail("htu", fmt.Sprintf("htu claim %q does not parse as a URI: %v", htu, err))
		return
	}
	want, err := normalizeHTU(exp.URL)
	if err != nil {
		r.fail("htu", fmt.Sprintf("--url %q does not parse as a URI: %v", exp.URL, err))
		return
	}
	if got != want {
		r.fail("htu", fmt.Sprintf("proof is bound to %s but the request targets %s (comparison ignores query and fragment)", got, want))
		return
	}
	r.ok("htu", fmt.Sprintf("bound to %s", got))
}

// normalizeHTU applies RFC 9449 §4.3 comparison: query and fragment are
// ignored, scheme and host are case-insensitive, default ports drop.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URI must be absolute with scheme and host")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch scheme {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func checkTimes(r *Result, claims map[string]any, exp Expect) {
	iat, ok := numClaim(claims, "iat")
	if !ok {
		r.fail("iat", "claims have no numeric iat (issued-at) member")
	} else {
		age := exp.Now - iat
		switch {
		case age < -exp.Skew:
			r.fail("iat", fmt.Sprintf("issued %d s in the future (iat=%d, now=%d, skew=%d) — check clock sync between client and verifier", -age, iat, exp.Now, exp.Skew))
		case age > exp.MaxAge+exp.Skew:
			r.fail("iat", fmt.Sprintf("proof is %d s old, older than the acceptance window of %d s (iat=%d, now=%d) — DPoP proofs are meant to be minted per request", age, exp.MaxAge, iat, exp.Now))
		default:
			r.ok("iat", fmt.Sprintf("issued %d s ago, within the %d s window", age, exp.MaxAge))
		}
	}
	if expClaim, ok := numClaim(claims, "exp"); ok {
		if expClaim < exp.Now-exp.Skew {
			r.fail("exp", fmt.Sprintf("proof expired %d s ago (exp=%d, now=%d)", exp.Now-expClaim, expClaim, exp.Now))
		} else {
			r.ok("exp", "not yet expired")
		}
	}
	if nbf, ok := numClaim(claims, "nbf"); ok {
		if nbf > exp.Now+exp.Skew {
			r.fail("nbf", fmt.Sprintf("proof is not valid for another %d s (nbf=%d, now=%d)", nbf-exp.Now, nbf, exp.Now))
		} else {
			r.ok("nbf", "already valid")
		}
	}
}

func checkNonce(r *Result, claims map[string]any, exp Expect) {
	nonce, present := claims["nonce"].(string)
	if exp.Nonce == "" {
		if present {
			r.skip("nonce", "proof carries a nonce; pass --nonce to check it against the server-issued value")
		}
		return
	}
	if !present {
		r.fail("nonce", "server issued a nonce (--nonce) but the proof has no nonce claim — the client must retry with the DPoP-Nonce header value")
		return
	}
	if nonce != exp.Nonce {
		r.fail("nonce", "nonce claim does not match the server-issued value — stale nonce, client must retry with the latest DPoP-Nonce")
		return
	}
	r.ok("nonce", "matches the server-issued value")
}

func checkATH(r *Result, claims map[string]any, exp Expect) {
	ath, present := claims["ath"].(string)
	if exp.AccessToken == "" {
		if present {
			r.skip("ath", "proof binds an access token; pass --access-token to check the hash")
		}
		return
	}
	sum := sha256.Sum256([]byte(exp.AccessToken))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if !present {
		r.fail("ath", fmt.Sprintf("resource-server requests must bind the access token, but the proof has no ath claim (expected %s)", want))
		return
	}
	if ath != want {
		r.fail("ath", fmt.Sprintf("ath is %s but SHA-256 of the presented access token is %s — the proof was minted for a different token", ath, want))
		return
	}
	r.ok("ath", "matches SHA-256 of the presented access token")
}

func checkJKT(r *Result, exp Expect) {
	if exp.JKT == "" {
		return
	}
	if r.Thumbprint == "" {
		r.fail("jkt", "cannot compare cnf.jkt: the embedded key has no computable thumbprint")
		return
	}
	if r.Thumbprint != exp.JKT {
		r.fail("jkt", fmt.Sprintf("access token is bound to key %s but the proof key thumbprint is %s — the proof was signed with a different key than the token was issued to", exp.JKT, r.Thumbprint))
		return
	}
	r.ok("jkt", "proof key matches the token's cnf.jkt binding")
}

func numClaim(claims map[string]any, name string) (int64, bool) {
	n, ok := claims[name].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
}

func indentJSON(m map[string]any) string {
	b, err := json.MarshalIndent(m, "  ", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
