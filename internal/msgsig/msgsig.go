// Package msgsig orchestrates RFC 9421 verification for a parsed HTTP
// message: it pairs Signature-Input with Signature, rebuilds the
// signature base per label, resolves the algorithm, applies the time
// window, checks the cryptography, and cross-checks Content-Digest —
// emitting a named check with an explanation for every rule on the way.
package msgsig

import (
	"fmt"
	"strings"
	"time"

	"github.com/JaydenCJ/httpsigcheck/internal/digest"
	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/keys"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
	"github.com/JaydenCJ/httpsigcheck/internal/sigbase"
	"github.com/JaydenCJ/httpsigcheck/internal/verify"
)

// Options tunes verification.
type Options struct {
	Scheme string   // assumed scheme for derived components
	Labels []string // verify only these labels; empty = all present
	Alg    string   // force this algorithm regardless of hints
	Now    int64    // verification time (unix seconds)
	Skew   int64    // tolerated clock skew, seconds
	MaxAge int64    // when >0, reject signatures older than this
}

// SigResult is the outcome for one signature label.
type SigResult struct {
	Label  string
	Alg    string // resolved algorithm, with its provenance in the checks
	Params sigbase.SigParams
	Base   *sigbase.Base // nil when reconstruction failed
	Checks []report.Check
}

// OK reports whether every check for this signature passed.
func (s *SigResult) OK() bool { return report.AllOK(s.Checks) }

// Result is the outcome for a whole message.
type Result struct {
	Checks     []report.Check // message-level checks
	Signatures []SigResult
	Digests    []digest.Result
}

// OK reports the overall verdict.
func (r *Result) OK() bool {
	if !report.AllOK(r.Checks) {
		return false
	}
	for i := range r.Signatures {
		if !r.Signatures[i].OK() {
			return false
		}
	}
	for _, d := range r.Digests {
		if d.Status == "mismatch" || d.Status == "malformed" {
			return false
		}
	}
	return true
}

func (r *Result) fail(name, detail string) {
	r.Checks = append(r.Checks, report.Check{Name: name, Status: report.StatusFail, Detail: detail})
}

// Verify checks every selected signature on the message with one key.
func Verify(msg *httpmsg.Message, key *keys.Key, opts Options) *Result {
	r := &Result{}
	r.Digests = digest.Check(msg)

	inputs, sigs, ok := parseSignatureFields(msg, r)
	if !ok {
		return r
	}

	labels, ok := selectLabels(inputs, opts.Labels, r)
	if !ok {
		return r
	}

	for _, label := range labels {
		member, _ := inputs.Get(label)
		r.Signatures = append(r.Signatures, verifyOne(msg, key, label, member, sigs, opts))
	}
	return r
}

// parseSignatureFields reads and parses the Signature-Input and
// Signature dictionaries, reporting message-level failures.
func parseSignatureFields(msg *httpmsg.Message, r *Result) (inputs, sigs *sfv.Dictionary, ok bool) {
	inputVals := msg.Values("Signature-Input")
	if inputVals == nil {
		r.fail("signature-input", "message has no Signature-Input field — there is nothing to verify (is the signature on a different hop?)")
		return nil, nil, false
	}
	inputs, err := sfv.ParseDictionary(strings.Join(inputVals, ", "))
	if err != nil {
		r.fail("signature-input", fmt.Sprintf("field does not parse as an RFC 8941 Dictionary: %v", err))
		return nil, nil, false
	}
	if len(inputs.Entries) == 0 {
		r.fail("signature-input", "field is present but contains no signature labels")
		return nil, nil, false
	}

	sigVals := msg.Values("Signature")
	if sigVals == nil {
		r.fail("signature", "message has a Signature-Input field but no Signature field carrying the actual signature bytes")
		return nil, nil, false
	}
	sigs, err = sfv.ParseDictionary(strings.Join(sigVals, ", "))
	if err != nil {
		r.fail("signature", fmt.Sprintf("field does not parse as an RFC 8941 Dictionary: %v", err))
		return nil, nil, false
	}
	return inputs, sigs, true
}

func selectLabels(inputs *sfv.Dictionary, want []string, r *Result) ([]string, bool) {
	var have []string
	for _, e := range inputs.Entries {
		have = append(have, e.Key)
	}
	if len(want) == 0 {
		return have, true
	}
	for _, label := range want {
		if _, ok := inputs.Get(label); !ok {
			r.fail("label", fmt.Sprintf("requested label %q is not in Signature-Input (present: %s)",
				label, strings.Join(have, ", ")))
			return nil, false
		}
	}
	return want, true
}

// verifyOne runs the full check sequence for a single signature label.
func verifyOne(msg *httpmsg.Message, key *keys.Key, label string, member sfv.Member, sigs *sfv.Dictionary, opts Options) SigResult {
	s := SigResult{Label: label}
	ok := func(name, detail string) {
		s.Checks = append(s.Checks, report.Check{Name: name, Status: report.StatusOK, Detail: detail})
	}
	fail := func(name, detail string) {
		s.Checks = append(s.Checks, report.Check{Name: name, Status: report.StatusFail, Detail: detail})
	}
	skip := func(name, detail string) {
		s.Checks = append(s.Checks, report.Check{Name: name, Status: report.StatusSkip, Detail: detail})
	}

	// 1. The Signature-Input member must be an inner list of components.
	if !member.IsInner {
		fail("covered", "Signature-Input member is not an inner list of covered components")
		return s
	}
	covered := member.Inner

	// 2. Signature parameters must be well-typed.
	params, err := sigbase.ExtractParams(covered)
	if err != nil {
		fail("params", err.Error())
		return s
	}
	s.Params = params
	if len(params.Unknown) > 0 {
		skip("params", fmt.Sprintf("unrecognized signature parameters (%s) are included in the signed base but not enforced by this tool",
			strings.Join(params.Unknown, ", ")))
	}

	// 3. The matching Signature member must exist and be a byte sequence.
	sigBytes, okSig := signatureBytes(sigs, label, fail)
	if !okSig {
		return s
	}

	// 4. Rebuild the signature base — the heart of the whole exercise.
	base, err := sigbase.Build(msg, covered, sigbase.Options{Scheme: opts.Scheme})
	if err != nil {
		fail("base", fmt.Sprintf("cannot reconstruct the signature base: %v", err))
		return s
	}
	s.Base = base
	ok("base", fmt.Sprintf("reconstructed: %d component %s + @signature-params",
		len(base.Lines), report.Plural(len(base.Lines), "line")))

	// 5. Resolve the algorithm and confirm it fits the key.
	alg, source, err := resolveAlg(params, key, opts)
	if err != nil {
		fail("alg", err.Error())
		return s
	}
	s.Alg = alg
	ok("alg", fmt.Sprintf("%s (%s)", alg, source))

	// 6. keyid consistency, when both sides name one.
	checkKeyID(params, key, ok, skip, fail)

	// 7. Time window.
	checkTimes(params, opts, ok, skip, fail)

	// 8. The actual cryptography, over the exact base bytes.
	if err := verify.Signature(alg, key, []byte(base.Text()), sigBytes); err != nil {
		fail("signature", err.Error()+" — either the message changed since signing, or the signer built a different base (compare the base above with the signer's)")
	} else {
		ok("signature", fmt.Sprintf("%d-byte signature verifies over the %d-byte base", len(sigBytes), len(base.Text())))
	}

	// 9. Body coverage: a valid signature pins the body only through
	// content-digest.
	checkBodyCoverage(msg, covered, ok, skip)
	return s
}

func signatureBytes(sigs *sfv.Dictionary, label string, fail func(name, detail string)) ([]byte, bool) {
	sigMember, ok := sigs.Get(label)
	if !ok {
		var have []string
		for _, e := range sigs.Entries {
			have = append(have, e.Key)
		}
		fail("signature", fmt.Sprintf("label %q has a Signature-Input entry but no Signature entry (Signature has: %s)",
			label, strings.Join(have, ", ")))
		return nil, false
	}
	if sigMember.IsInner || sigMember.Item.Bare.Type != sfv.TypeBytes {
		fail("signature", "Signature member must be a byte sequence (:base64:)")
		return nil, false
	}
	return sigMember.Item.Bare.Bytes, true
}

// resolveAlg picks the algorithm: an explicit --alg wins, then the alg
// signature parameter, then inference from the key type. The alg
// parameter is attacker-controlled input, so a mismatch against the key
// is a hard failure, not a fallback.
func resolveAlg(params sigbase.SigParams, key *keys.Key, opts Options) (alg, source string, err error) {
	switch {
	case opts.Alg != "":
		alg, source = opts.Alg, "forced by --alg"
		if params.Alg != "" && params.Alg != opts.Alg {
			source += fmt.Sprintf("; note: the signature's alg parameter says %q", params.Alg)
		}
	case params.Alg != "":
		alg, source = params.Alg, "from the alg signature parameter"
	default:
		alg, err = verify.ForKey(key)
		if err != nil {
			return "", "", err
		}
		source = "inferred from the key type"
		if key.IsRSA() {
			source += "; RSA is ambiguous, assuming the registry default (override with --alg rsa-v1_5-sha256 if needed)"
		}
	}
	if err := verify.CompatibleWithKey(alg, key); err != nil {
		return "", "", err
	}
	return alg, source, nil
}

func checkKeyID(params sigbase.SigParams, key *keys.Key, ok, skip, fail func(name, detail string)) {
	switch {
	case params.KeyID == "":
		skip("keyid", "signature names no keyid; make sure the key you supplied is the one the signer meant")
	case key.KeyID == "":
		skip("keyid", fmt.Sprintf("signature names keyid %q; the supplied key file carries no kid to compare (JWK files with a kid are compared automatically)", params.KeyID))
	case params.KeyID != key.KeyID:
		fail("keyid", fmt.Sprintf("signature was made with keyid %q but the supplied key is %q — you are verifying with the wrong key", params.KeyID, key.KeyID))
	default:
		ok("keyid", fmt.Sprintf("%q matches the supplied key", params.KeyID))
	}
}

func checkTimes(params sigbase.SigParams, opts Options, ok, skip, fail func(name, detail string)) {
	now := opts.Now
	if params.Created != nil {
		c := *params.Created
		age := now - c
		switch {
		case age < -opts.Skew:
			fail("created", fmt.Sprintf("signature claims creation %d s in the future (created=%d, now=%d, skew=%d) — check clock sync",
				-age, c, now, opts.Skew))
		case opts.MaxAge > 0 && age > opts.MaxAge+opts.Skew:
			fail("created", fmt.Sprintf("signature is %d s old, over the --max-age limit of %d s (created=%s)",
				age, opts.MaxAge, time.Unix(c, 0).UTC().Format(time.RFC3339)))
		default:
			ok("created", fmt.Sprintf("%s (%d s ago)", time.Unix(c, 0).UTC().Format(time.RFC3339), age))
		}
	} else if opts.MaxAge > 0 {
		fail("created", "--max-age was requested but the signature carries no created parameter")
	} else {
		skip("created", "signature carries no created parameter; its age cannot be judged")
	}

	if params.Expires != nil {
		e := *params.Expires
		if e < now-opts.Skew {
			fail("expires", fmt.Sprintf("signature expired %d s ago (expires=%s, now=%s)",
				now-e, time.Unix(e, 0).UTC().Format(time.RFC3339), time.Unix(now, 0).UTC().Format(time.RFC3339)))
		} else {
			ok("expires", fmt.Sprintf("valid for another %d s", e-now))
		}
	}
}

// checkBodyCoverage explains what a passing signature does and does not
// pin: without content-digest in the covered components, the body can
// be swapped without breaking the signature.
func checkBodyCoverage(msg *httpmsg.Message, covered sfv.InnerList, ok, skip func(name, detail string)) {
	coversDigest := false
	for _, it := range covered.Items {
		if it.Bare.Type == sfv.TypeString && it.Bare.Str == "content-digest" {
			coversDigest = true
			break
		}
	}
	switch {
	case coversDigest:
		ok("body", "signature covers content-digest, binding the body (see the digest check below)")
	case len(msg.Body) > 0:
		skip("body", fmt.Sprintf("message has a %d-byte body but the signature does not cover content-digest — the body is NOT protected by this signature", len(msg.Body)))
	default:
		skip("body", "signature does not cover content-digest (message has no body)")
	}
}
