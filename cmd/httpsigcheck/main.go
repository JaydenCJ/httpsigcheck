// Command httpsigcheck verifies RFC 9421 HTTP Message Signatures and
// RFC 9449 DPoP proofs offline, and explains failures by showing the
// exact reconstructed signature base.
package main

import (
	"os"

	"github.com/JaydenCJ/httpsigcheck/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
