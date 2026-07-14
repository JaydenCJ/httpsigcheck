// httpsigcheck — verifies RFC 9421 HTTP Message Signatures and RFC 9449
// DPoP proofs offline, and explains failures by showing the exact
// reconstructed signature base.
//
// version:    0.1.0
// author:     JaydenCJ
// license:    MIT
// repository: https://github.com/JaydenCJ/httpsigcheck
// keywords:   http-signatures, rfc9421, dpop, oauth, security, debugging, cli
//
// Zero runtime dependencies: standard library only.
module github.com/JaydenCJ/httpsigcheck

go 1.22
