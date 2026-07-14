# httpsigcheck examples

Static, self-contained inputs — every command below runs offline. All
timestamps are pinned to `1783814400` (2026-07-12T00:00:00Z), so pass
`--now 1783814400` to reproduce the exact outputs shown in the README.

## signed-request.http + ed25519-public.pem

A payments-style POST signed per RFC 9421 (Ed25519, four covered
components including `content-digest`):

```bash
httpsigcheck verify --key examples/ed25519-public.pem --now 1783814400 examples/signed-request.http
httpsigcheck base examples/signed-request.http     # just the signature base
```

## tampered-request.http

The same message with the amount changed in the body (`"amount":10` →
`"amount":900`). The signature still verifies — it covers the digest
*field*, not the body — and the Content-Digest check is what catches
the swap:

```bash
httpsigcheck verify --key examples/ed25519-public.pem --now 1783814400 examples/tampered-request.http
echo "exit: $?"   # 1
```

## dpop-proof.jwt

An ES256 DPoP proof bound to `POST https://as.example.test/token`, with
its P-256 public key embedded in the header (thumbprint
`0hIJc9x8a1ZPgKvi46zZs9i7Q-X2xwEseMpnBR3Hq24`):

```bash
httpsigcheck dpop --method POST --url https://as.example.test/token --now 1783814400 examples/dpop-proof.jwt
# check the cnf.jkt binding too:
httpsigcheck dpop --method POST --url https://as.example.test/token --now 1783814400 \
  --jkt 0hIJc9x8a1ZPgKvi46zZs9i7Q-X2xwEseMpnBR3Hq24 examples/dpop-proof.jwt
```

The files were produced with the deterministic keys in
`internal/fixture`, so regenerating them yields byte-identical
signatures for the Ed25519 message (ECDSA signatures are randomized but
verify identically).
