// Package cli implements the httpsigcheck command-line interface. Run
// takes argv and two writers and returns an exit code, so the whole
// surface is testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JaydenCJ/httpsigcheck/internal/version"
)

// Exit codes, documented in the README.
const (
	ExitOK      = 0 // everything verified
	ExitFail    = 1 // verification failed (the interesting exit code)
	ExitUsage   = 2 // bad flags or arguments
	ExitRuntime = 3 // unreadable files, unparsable inputs
)

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "base":
		return runBase(args[1:], stdout, stderr)
	case "dpop":
		return runDPoP(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "httpsigcheck %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "httpsigcheck: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `httpsigcheck — verify RFC 9421 HTTP Message Signatures and DPoP proofs offline

Usage:
  httpsigcheck verify --key FILE [flags] <message.http>   verify message signatures
  httpsigcheck base   [flags] <message.http>              print the reconstructed signature base
  httpsigcheck dpop   [flags] <proof.jwt | ->             verify a DPoP proof JWT
  httpsigcheck version                                    print the version

Shared flags (verify and dpop):
  --now TIME       verification time (unix seconds or RFC 3339); defaults to the wall clock
  --skew SECONDS   tolerated clock skew (default 30)
  --format FORMAT  text (default) or json

verify flags:
  --key FILE       public key: PEM (PKIX/PKCS#1/certificate) or JWK JSON
  --secret VALUE   hmac-sha256 shared secret (raw, or "base64:...")
  --label NAME     verify only this signature label (repeatable; default: all)
  --alg NAME       force the signature algorithm, overriding the alg parameter
  --scheme NAME    scheme assumed for derived components (default https)
  --max-age SECS   reject signatures whose created is older than this

base flags:
  --label NAME             print only this label's base
  --scheme NAME            scheme assumed for derived components (default https)
  --components 'LIST'      build a base for this covered-components inner list
                           instead of reading Signature-Input, e.g.
                           '("@method" "@path");created=1618884473;keyid="k"'

dpop flags:
  --method NAME            expected htm claim
  --url URL                expected htu claim (query and fragment are ignored)
  --access-token VALUE     access token to check the ath hash against
  --jkt THUMBPRINT         expected RFC 7638 key thumbprint (cnf.jkt binding)
  --nonce VALUE            server-issued nonce the proof must echo
  --max-age SECS           acceptance window for iat (default 300)

Exit codes: 0 verified, 1 verification failed, 2 usage error, 3 input error.
`)
}

// parseNow accepts unix seconds or RFC 3339 and pins verification time;
// deterministic runs (tests, CI, forensics on captured traffic) depend
// on it.
func parseNow(s string) (int64, error) {
	if s == "" {
		return time.Now().Unix(), nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("--now must be unix seconds or RFC 3339, got %q", s)
	}
	return t.Unix(), nil
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// newFlagSet builds a silent FlagSet whose errors we report ourselves.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// oneArg extracts the single positional argument (the message or proof
// file) after flag parsing.
func oneArg(fs *flag.FlagSet, what string, stderr io.Writer) (string, bool) {
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "httpsigcheck: expected exactly one %s argument, got %d\n", what, fs.NArg())
		return "", false
	}
	return fs.Arg(0), true
}

// readInput reads a file, with "-" meaning stdin.
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func checkFormat(format string, stderr io.Writer) bool {
	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "httpsigcheck: --format must be text or json, got %q\n", format)
		return false
	}
	return true
}
