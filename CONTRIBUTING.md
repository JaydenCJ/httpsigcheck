# Contributing to httpsigcheck

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — no C toolchain, no external services.

```bash
git clone https://github.com/JaydenCJ/httpsigcheck && cd httpsigcheck
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives every subcommand
against the committed example files with a pinned clock, asserting on
real output and exit codes; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (89 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules — parsing, base construction, and crypto never touch the
   filesystem or clock directly (the CLI injects both).

## Ground rules

- Keep dependencies at zero: the Go standard library covers structured
  fields, HTTP parsing, and every registered algorithm. Adding a
  dependency needs a very strong case in the PR.
- No network calls, ever. httpsigcheck is an offline verifier by
  design — keys and messages come from files and flags. No telemetry.
- Spec rules are data where possible: new structured-field types go
  into the registry in `internal/sigbase`, new algorithms into
  `internal/verify`, each with a test citing the RFC section.
- Failure messages are part of the interface: every new check must say
  what failed, show the relevant values, and hint at the fix. Tests
  assert on these strings.
- Code comments and doc comments are written in English.
- Determinism first: identical input plus an identical `--now` must
  produce byte-identical reports.

## Reporting bugs

Include the output of `httpsigcheck version`, the full command you ran,
the report output, and — for base mismatches — the signer's own
signature base if you can get it, since diffing the two bases is how
these bugs are located. Redact key material and tokens; the message
head and covered component list are usually enough.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
