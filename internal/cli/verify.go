package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/JaydenCJ/httpsigcheck/internal/digest"
	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/keys"
	"github.com/JaydenCJ/httpsigcheck/internal/msgsig"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
	"github.com/JaydenCJ/httpsigcheck/internal/version"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	var (
		keyFile = fs.String("key", "", "public key file (PEM or JWK)")
		secret  = fs.String("secret", "", "hmac-sha256 shared secret")
		alg     = fs.String("alg", "", "force the signature algorithm")
		scheme  = fs.String("scheme", "https", "scheme assumed for derived components")
		nowFlag = fs.String("now", "", "verification time (unix seconds or RFC 3339)")
		skew    = fs.Int64("skew", 30, "tolerated clock skew in seconds")
		maxAge  = fs.Int64("max-age", 0, "reject signatures older than this many seconds")
		format  = fs.String("format", "text", "output format: text or json")
		labels  multiFlag
	)
	fs.Var(&labels, "label", "verify only this signature label (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !checkFormat(*format, stderr) {
		return ExitUsage
	}
	path, ok := oneArg(fs, "message file", stderr)
	if !ok {
		return ExitUsage
	}
	if (*keyFile == "") == (*secret == "") {
		fmt.Fprintln(stderr, "httpsigcheck: exactly one of --key or --secret is required")
		return ExitUsage
	}
	now, err := parseNow(*nowFlag)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
		return ExitUsage
	}

	key, err := loadKey(*keyFile, *secret)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
		return ExitRuntime
	}
	raw, err := readInput(path)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
		return ExitRuntime
	}
	msg, err := httpmsg.Parse(raw)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %s: %v\n", path, err)
		return ExitRuntime
	}

	result := msgsig.Verify(msg, key, msgsig.Options{
		Scheme: *scheme,
		Labels: labels,
		Alg:    *alg,
		Now:    now,
		Skew:   *skew,
		MaxAge: *maxAge,
	})

	if *format == "json" {
		writeVerifyJSON(stdout, path, msg, result)
	} else {
		writeVerifyText(stdout, path, msg, result)
	}
	if result.OK() {
		return ExitOK
	}
	return ExitFail
}

func loadKey(keyFile, secret string) (*keys.Key, error) {
	if secret != "" {
		return keys.Shared(secret)
	}
	data, err := readInput(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := keys.LoadPublic(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	return key, nil
}

func describeMessage(msg *httpmsg.Message) string {
	fields := fmt.Sprintf("%d %s", len(msg.Headers), report.Plural(len(msg.Headers), "header field"))
	if msg.IsResponse {
		return fmt.Sprintf("response, status %d, %s, %d-byte body",
			msg.StatusCode, fields, len(msg.Body))
	}
	return fmt.Sprintf("%s request for %s, %s, %d-byte body",
		msg.Method, msg.RequestTarget, fields, len(msg.Body))
}

func writeVerifyText(w io.Writer, path string, msg *httpmsg.Message, r *msgsig.Result) {
	fmt.Fprintf(w, "httpsigcheck verify — %s\n", path)
	fmt.Fprintf(w, "message: %s\n", describeMessage(msg))

	if len(r.Checks) > 0 {
		fmt.Fprintln(w)
		report.WriteChecks(w, "  ", r.Checks)
	}

	valid := 0
	for i := range r.Signatures {
		s := &r.Signatures[i]
		if s.OK() {
			valid++
		}
		fmt.Fprintf(w, "\nsignature %q\n", s.Label)
		if s.Base != nil {
			fmt.Fprintln(w, "  signature base:")
			report.WriteBlock(w, "    | ", s.Base.Text())
		}
		fmt.Fprintln(w, "  checks:")
		report.WriteChecks(w, "    ", s.Checks)
	}

	if len(r.Digests) > 0 {
		fmt.Fprintln(w, "\ncontent-digest:")
		for _, d := range r.Digests {
			fmt.Fprintf(w, "  %-8s %s  %s\n", d.Alg, report.Glyph(digestStatus(d.Status)), d.Detail)
		}
	}

	fmt.Fprintf(w, "\nverify: %s (%s)\n", report.Verdict(r.OK()), verdictDetail(r, valid))
}

// verdictDetail explains the final verdict in one clause. The subtle
// case is FAIL with every signature valid: only a content-digest
// mismatch can cause it (message-level check failures leave no
// signatures behind), and saying so keeps the verdict line from
// contradicting the checks above it.
func verdictDetail(r *msgsig.Result, valid int) string {
	total := len(r.Signatures)
	if total == 0 {
		return "no signature could be checked"
	}
	detail := fmt.Sprintf("%d of %d %s valid", valid, total, report.Plural(total, "signature"))
	if !r.OK() && valid == total {
		detail += ", but a content-digest check failed"
	}
	return detail
}

// digestStatus maps RFC 9530 check outcomes onto the shared check
// statuses for rendering.
func digestStatus(s string) string {
	switch s {
	case "ok":
		return report.StatusOK
	case "unsupported":
		return report.StatusSkip
	default: // mismatch, malformed
		return report.StatusFail
	}
}

// verifyJSON is the stable machine-readable envelope (schema_version 1).
type verifyJSON struct {
	Tool          string          `json:"tool"`
	Version       string          `json:"version"`
	SchemaVersion int             `json:"schema_version"`
	Input         string          `json:"input"`
	Message       string          `json:"message"`
	Checks        []report.Check  `json:"checks,omitempty"`
	Signatures    []signatureJSON `json:"signatures"`
	ContentDigest []digest.Result `json:"content_digest,omitempty"`
	OK            bool            `json:"ok"`
}

type signatureJSON struct {
	Label  string         `json:"label"`
	Alg    string         `json:"alg,omitempty"`
	KeyID  string         `json:"keyid,omitempty"`
	Base   string         `json:"base,omitempty"`
	Checks []report.Check `json:"checks"`
	OK     bool           `json:"ok"`
}

func writeVerifyJSON(w io.Writer, path string, msg *httpmsg.Message, r *msgsig.Result) {
	out := verifyJSON{
		Tool:          "httpsigcheck",
		Version:       version.Version,
		SchemaVersion: 1,
		Input:         path,
		Message:       describeMessage(msg),
		Checks:        r.Checks,
		Signatures:    []signatureJSON{},
		ContentDigest: r.Digests,
		OK:            r.OK(),
	}
	for i := range r.Signatures {
		s := &r.Signatures[i]
		sj := signatureJSON{Label: s.Label, Alg: s.Alg, KeyID: s.Params.KeyID, Checks: s.Checks, OK: s.OK()}
		if s.Base != nil {
			sj.Base = s.Base.Text()
		}
		out.Signatures = append(out.Signatures, sj)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
