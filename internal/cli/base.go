package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/httpsigcheck/internal/httpmsg"
	"github.com/JaydenCJ/httpsigcheck/internal/sfv"
	"github.com/JaydenCJ/httpsigcheck/internal/sigbase"
)

// runBase prints the reconstructed signature base — the exact bytes a
// signer must sign — either from the message's own Signature-Input or
// from an ad-hoc --components list. Diffing this output against a
// signer's log is the fastest way to find a base mismatch.
func runBase(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("base", stderr)
	var (
		scheme     = fs.String("scheme", "https", "scheme assumed for derived components")
		label      = fs.String("label", "", "print only this label's base")
		components = fs.String("components", "", "covered-components inner list to build a base for")
	)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	path, ok := oneArg(fs, "message file", stderr)
	if !ok {
		return ExitUsage
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
	opts := sigbase.Options{Scheme: *scheme}

	if *components != "" {
		il, err := sfv.ParseInnerList(*components)
		if err != nil {
			fmt.Fprintf(stderr, "httpsigcheck: --components: %v\n", err)
			return ExitUsage
		}
		base, err := sigbase.Build(msg, il, opts)
		if err != nil {
			fmt.Fprintf(stderr, "httpsigcheck: %v\n", err)
			return ExitFail
		}
		fmt.Fprintln(stdout, base.Text())
		return ExitOK
	}

	inputVals := msg.Values("Signature-Input")
	if inputVals == nil {
		fmt.Fprintln(stderr, "httpsigcheck: message has no Signature-Input field; pass --components to build a base without one")
		return ExitFail
	}
	inputs, err := sfv.ParseDictionary(strings.Join(inputVals, ", "))
	if err != nil {
		fmt.Fprintf(stderr, "httpsigcheck: Signature-Input does not parse: %v\n", err)
		return ExitFail
	}

	printed := 0
	for _, e := range inputs.Entries {
		if *label != "" && e.Key != *label {
			continue
		}
		if !e.Value.IsInner {
			fmt.Fprintf(stderr, "httpsigcheck: label %q: Signature-Input member is not an inner list\n", e.Key)
			return ExitFail
		}
		base, err := sigbase.Build(msg, e.Value.Inner, opts)
		if err != nil {
			fmt.Fprintf(stderr, "httpsigcheck: label %q: %v\n", e.Key, err)
			return ExitFail
		}
		// With several labels, separate the bases with comment lines so
		// the output stays diffable one label at a time.
		if len(inputs.Entries) > 1 && *label == "" {
			if printed > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintf(stdout, "# label %q\n", e.Key)
		}
		fmt.Fprintln(stdout, base.Text())
		printed++
	}
	if printed == 0 {
		fmt.Fprintf(stderr, "httpsigcheck: label %q is not in Signature-Input\n", *label)
		return ExitFail
	}
	return ExitOK
}
