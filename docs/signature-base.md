# How httpsigcheck rebuilds the signature base

RFC 9421 signatures are not computed over raw bytes on the wire. Signer
and verifier each *derive* a canonical text — the **signature base** —
from the message and the covered component list, and the signature is
over that text. Almost every real-world verification failure is the two
sides deriving different bases, which is why `httpsigcheck base` prints
the verifier's derivation for you to diff against the signer's.

## Shape of the base

One line per covered component, then the `@signature-params` line,
joined with `\n` and **no trailing newline**:

```text
"@method": POST
"@authority": api.example.test
"content-digest": sha-256=:nVlzC8VTtrocY1BHIIbbI7A+znTUnXEwu82/38042Y8=:
"@signature-params": ("@method" "@authority" "content-digest");created=1783814400;keyid="payments-key-1"
```

The last line is the *canonical re-serialization* of the parsed
Signature-Input member — spacing is normalized, parameter order is
preserved. A signer that emits non-canonical structured fields will
produce signatures nobody can verify.

## HTTP field components

| Rule | Effect |
|---|---|
| lookup | case-insensitive; the identifier itself must be lowercase |
| multiple instances | values joined in order with `", "` |
| whitespace | leading/trailing trimmed per value; obs-fold collapsed to one space |
| `;sf` | re-serialize canonically per the field's registered structured type |
| `;key="m"` | parse as Dictionary, serialize only member `m` |
| `;bs` | wrap each instance's raw bytes as `:base64:` before joining |
| `;req`, `;tr` | not supported in v0.1.0 (clear error, see Roadmap) |

`;sf` needs to know the field's registered type; the built-in registry
covers the Dictionary/List/Item fields registered for structured-field
use (content-digest, repr-digest, signature, signature-input, priority,
accept-ch, cache-status, proxy-status, client-cert, and friends). For a
field outside the registry the error says exactly that.

## Derived components

| Component | Source | Notes |
|---|---|---|
| `@method` | request line | verbatim (methods are case-sensitive) |
| `@request-target` | request line | verbatim |
| `@path` | request target | query stripped; empty path becomes `/` |
| `@query` | request target | includes leading `?`; absent query is `?` |
| `@query-param;name="x"` | request target | form-urlencoded decode, strict re-encode; one line per occurrence |
| `@authority` | Host field | lowercased, default port stripped |
| `@scheme` | `--scheme` flag | HTTP/1.1 messages do not name their scheme; default `https` |
| `@target-uri` | all of the above | `scheme://authority/path?query` |
| `@status` | status line | responses only |

The `@query-param` normalization (decode, then re-encode with only
unreserved characters literal, uppercase hex otherwise) is what makes
`?q=hello+world` and `?q=hello%20world` sign identically — and what
stops encoding tricks from smuggling a different value past a verifier.

## Failure catalog

Every failed check names the rule and says what to do next:

| Check | Typical cause |
|---|---|
| `base` | covered field stripped by a proxy, wrong `--scheme`, `;key` member missing |
| `alg` | alg parameter contradicts the key type (fails closed — this is attacker-controlled input) |
| `keyid` | verifying with a different key than the signer named |
| `created` / `expires` | clock skew, replayed old signature, `--max-age` exceeded |
| `signature` | message modified in a covered component, or the signer built a different base — diff `httpsigcheck base` output against the signer's log |
| digest `mismatch` | body swapped after signing; the signature can still be valid, the digest is what pins the payload |
