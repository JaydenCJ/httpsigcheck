# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Full RFC 9421 signature-base reconstruction: HTTP field components
  (multi-instance joining, obs-fold, `;sf` canonical re-serialization
  against a structured-type registry, `;key` Dictionary member
  extraction, `;bs` byte wrapping) and all request/response derived
  components (`@method`, `@target-uri`, `@authority`, `@scheme`,
  `@request-target`, `@path`, `@query`, `@query-param` with strict
  re-encoding and repeated-name handling, `@status`).
- `verify` subcommand checking every signature label on a raw HTTP
  message: base reconstruction, algorithm resolution with key/alg
  confusion rejection, `created`/`expires`/`--max-age` time window,
  keyid consistency, and the cryptographic check itself — every rule a
  named check with an explanation, plus the reconstructed base in the
  output.
- All six registered signature algorithms: rsa-pss-sha512,
  rsa-v1_5-sha256, hmac-sha256, ecdsa-p256-sha256 and
  ecdsa-p384-sha384 (raw r||s, with an ASN.1-DER hint on wrong-length
  signatures), and ed25519.
- RFC 9530 Content-Digest checking (sha-256/sha-512) against the exact
  body bytes, with body-coverage diagnostics ("signature valid but body
  not bound").
- `base` subcommand printing the reconstructed signature base for
  diffing against a signer's log, including `--components` for ad-hoc
  coverage without a Signature-Input field.
- `dpop` subcommand verifying RFC 9449 proofs offline: JWS signature
  with the embedded JWK (ES256/ES384/ES512/RS256/PS256/EdDSA; `none`
  and HS* rejected by name), private-key-leak detection, and the
  htm/htu/iat/exp/nbf/jti/ath/nonce claim checks with RFC 7638
  thumbprint computation for `cnf.jkt` binding.
- Key loading from PEM (PKIX, PKCS#1, certificates) and JWK documents,
  plus `--secret` shared secrets for HMAC.
- Deterministic verification via `--now`/`--skew`, stable JSON output
  (`schema_version: 1`), exit codes 0/1/2/3, and an RFC 8941
  structured-field parser/serializer built for canonical round trips.
- Static runnable examples (signed request, tampered twin, DPoP proof)
  and a signature-base guide (`docs/signature-base.md`).
- 89 deterministic offline tests (hand-derived known-answer bases,
  crypto round trips, in-process CLI integration) and
  `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/httpsigcheck/releases/tag/v0.1.0
