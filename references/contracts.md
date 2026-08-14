# CLI and result-v1 contracts

This reference defines the stable automation boundary for `ednsdiag`. Protocol
and provider behavior remains governed by `standards.md`, `security.md`, and
`providers.md`.

## Operations

`query` and `probe` perform one encrypted DNS exchange with the same validated
inputs. They differ only in the `operation` label so an agent can distinguish a
lookup from an explicit connectivity diagnostic without interpreting prose.

`compare` requires 2–8 explicit, unique targets in
`protocol:provider[:method]` form. It starts each target independently under
the same total deadline, retains target order, and returns the complete
per-target result in `attempts`.
It never merges, ranks, or treats differing answers as interchangeable.

## Input policy

- Record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `SRV`,
  `PTR`, `HTTPS`, and `SVCB`.
- Normal domain inputs are converted to lowercase IDNA ASCII before encoding.
- `PTR` uniquely accepts an IPv4 or IPv6 literal and converts it to the
  corresponding `in-addr.arpa` or `ip6.arpa` question.
- Other IP literals and `localhost`, `.local`, `.internal`, `.lan`, and `.arpa`
  names are rejected.
- Only built-in provider endpoints may be selected. The CLI does not accept an
  arbitrary resolver URL or address.
- Single-operation timeouts are `250ms`–`30s`. Compare total timeouts are
  `250ms`–`60s`; per-attempt timeouts are `250ms`–`30s` and no greater than the
  total timeout.
- Compare defaults to at most four attempts and never permits more than eight.
- DoH and DoT accept one shared `--proxy` value in absolute `http://` or
  `https://` URL form. It overrides environment selection. Without the flag,
  those transports use Go's standard `HTTPS_PROXY` and `NO_PROXY` rules.
- Explicit proxy use with DoH3, DoQ, DNSCrypt, ODoH, or Anonymized DNSCrypt is
  rejected; a TCP HTTP CONNECT proxy cannot carry their current UDP/QUIC paths.

## stdout, stderr, and exit status

Successful parsing produces one `result-v1` JSON document on stdout, including
structured transport, protocol, and unsupported failures. Human-readable CLI
usage diagnostics and JSON-encoding failures go to stderr. Usage failures do
not emit partial JSON.

| Exit | Contract |
| --- | --- |
| `0` | Operation completed. DNS RCODE may still be non-`NOERROR`. |
| `1` | Local/internal failure or output encoding failure. |
| `2` | Invalid arguments, input, timeout, domain, or record type. |
| `3` | Encrypted transport or DNS message protocol failure. |
| `4` | Known capability or provider/protocol combination is unsupported. |

DNS `NXDOMAIN`, `SERVFAIL`, `REFUSED`, and NODATA are completed DNS outcomes,
not transport errors, so their result exits with `0` when a valid response was
received.

## result-v1

Every operation uses `schema_version: 1` and validates against
`schemas/result-v1.schema.json`.

- `completed` describes completion of the encrypted exchange and DNS response
  parsing, not DNS success.
- `dns.rcode` and `dns.rcode_value` carry the resolver's DNS outcome.
- `dns.resolver_reports_dnssec_authenticated` is the resolver-reported AD bit.
- `dns.client_validated_dnssec` is always `false`; this client does not claim
  local DNSSEC validation.
- `transport.server_authenticated` is independent from DNSSEC.
- `transport.http_age_seconds`, when present, records the HTTP cache age
  subtracted from DoH and DoH3 answer TTLs.
- `transport.proxy`, when present, records the selected HTTP(S) proxy URL with
  userinfo removed. Its absence means no applicable proxy was selected.
- `compare.attempts` contains complete `query` results. `summary` only counts
  them; it does not replace or combine them.
- Record answers have type-specific stable fields. TXT character-strings are
  returned as an array without presentation-format quotes. MX, SRV, SOA,
  CAA, SVCB, and HTTPS components remain separately typed fields.
- Truncated DNS messages and answer data that cannot be represented by the v1
  type-specific contract are protocol failures, never completed results.

Adding an optional field is backward-compatible within v1. Removing a field,
renaming a field, changing its meaning or type, or changing command/exit
semantics requires a new schema version.
