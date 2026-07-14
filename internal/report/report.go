// Package report defines the named-check vocabulary every verifier in
// httpsigcheck speaks, and the text rendering shared by all subcommands.
// One rule, one check, one explanation — never a bare "invalid".
package report

import (
	"fmt"
	"io"
	"strings"
)

// Check statuses.
const (
	StatusOK   = "ok"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Check is one named verification step with its outcome and a
// human-readable explanation.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// AllOK reports whether no check in the list failed.
func AllOK(checks []Check) bool {
	for _, c := range checks {
		if c.Status == StatusFail {
			return false
		}
	}
	return true
}

// Glyph maps a status to its fixed-width text marker.
func Glyph(status string) string {
	switch status {
	case StatusOK:
		return "ok  "
	case StatusFail:
		return "FAIL"
	default:
		return "skip"
	}
}

// WriteChecks renders a check list as aligned text lines with the given
// indent.
func WriteChecks(w io.Writer, indent string, checks []Check) {
	width := 0
	for _, c := range checks {
		if len(c.Name) > width {
			width = len(c.Name)
		}
	}
	for _, c := range checks {
		fmt.Fprintf(w, "%s%-*s  %s  %s\n", indent, width, c.Name, Glyph(c.Status), c.Detail)
	}
}

// WriteBlock writes a multi-line string with each line prefixed by
// indent — used for signature bases and decoded JWT parts.
func WriteBlock(w io.Writer, indent, block string) {
	for _, line := range strings.Split(block, "\n") {
		fmt.Fprintf(w, "%s%s\n", indent, line)
	}
}

// Verdict renders the final PASS/FAIL line.
func Verdict(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// Plural returns the noun, adding a plain "s" unless n is 1 — every
// counted noun in the reports pluralizes regularly.
func Plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}
