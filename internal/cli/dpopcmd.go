package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/dpop"
	"github.com/JaydenCJ/httpsigcheck/internal/report"
	"github.com/JaydenCJ/httpsigcheck/internal/version"
)

func runDPoP(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("dpop", stderr)
	var (
		method  = fs.String("method", "", "expected htm claim")
		url     = fs.String("url", "", "expected htu claim")
		token   = fs.String("access-token", "", "access token to check ath against")
		jkt     = fs.String("jkt", "", "expected RFC 7638 key thumbprint")
		nonce   = fs.String("nonce", "", "server-issued nonce the proof must echo")
		nowFlag = fs.String("now", "", "verification time (unix seconds or RFC 3339)")
		skew    = fs.Int64("skew", 30, "tolerated clock skew in seconds")
		maxAge  = fs.Int64("max-age", 300, "acceptance window for iat in seconds")
		format  = fs.String("format", "text", "output format: text or json")
	)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !checkFormat(*format, stderr) {
		return ExitUsage
	}
	path, ok := oneArg(fs, "proof file", stderr)
	if !ok {
		return ExitUsage
	}
	now, err := parseNow(*nowFlag)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
		return ExitUsage
	}
	raw, err := readInput(path)
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
		return ExitRuntime
	}
	proof := strings.TrimSpace(string(raw))
	// Tolerate a pasted header line: "DPoP: eyJ..." or "DPoP eyJ...".
	proof = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(proof, "DPoP:"), "DPoP "))

	result := dpop.Verify(proof, dpop.Expect{
		Method:      *method,
		URL:         *url,
		AccessToken: *token,
		JKT:         *jkt,
		Nonce:       *nonce,
		Now:         now,
		Skew:        *skew,
		MaxAge:      *maxAge,
	})

	if *format == "json" {
		writeDPoPJSON(stdout, path, result)
	} else {
		writeDPoPText(stdout, path, result)
	}
	if result.OK() {
		return ExitOK
	}
	return ExitFail
}

func writeDPoPText(w io.Writer, path string, r *dpop.Result) {
	fmt.Fprintf(w, "httpsigcheck dpop — %s\n", path)
	if r.HeaderJSON != "" {
		fmt.Fprintf(w, "\nheader:\n  %s\nclaims:\n  %s\n", r.HeaderJSON, r.ClaimsJSON)
	}
	fmt.Fprintln(w, "\nchecks:")
	report.WriteChecks(w, "  ", r.Checks)
	if r.Thumbprint != "" {
		fmt.Fprintf(w, "\nkey thumbprint (cnf.jkt): %s\n", r.Thumbprint)
	}
	fmt.Fprintf(w, "\ndpop: %s\n", report.Verdict(r.OK()))
}

type dpopJSON struct {
	Tool          string         `json:"tool"`
	Version       string         `json:"version"`
	SchemaVersion int            `json:"schema_version"`
	Input         string         `json:"input"`
	Alg           string         `json:"alg,omitempty"`
	KeyKind       string         `json:"key_kind,omitempty"`
	Thumbprint    string         `json:"thumbprint,omitempty"`
	Checks        []report.Check `json:"checks"`
	OK            bool           `json:"ok"`
}

func writeDPoPJSON(w io.Writer, path string, r *dpop.Result) {
	out := dpopJSON{
		Tool:          "httpsigcheck",
		Version:       version.Version,
		SchemaVersion: 1,
		Input:         path,
		Alg:           r.Alg,
		KeyKind:       r.KeyKind,
		Thumbprint:    r.Thumbprint,
		Checks:        r.Checks,
		OK:            r.OK(),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
