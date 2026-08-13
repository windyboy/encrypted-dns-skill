# Security and privacy requirements

Read this file before changing transports, bootstrap behavior, endpoint
validation, fallback, or result claims.

## Non-negotiable rules

1. Never silently downgrade to plaintext DNS.
2. Validate certificates and authentication domain names. DoT follows the
   strict privacy profile in [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310.html).
3. Treat certificate, hostname, SNI, and negotiated ALPN mismatches as hard
   failures, not fallback opportunities.
4. Bound response sizes, per-attempt timeouts, total time, redirects, and the
   number of attempts.
5. Do not expose an unrestricted endpoint parameter to an Agent. Built-in
   providers are allowlisted; private or custom endpoints require explicit
   user intent and policy approval.
6. Do not connect to addresses returned in DNS answers.
7. Do not enable AXFR, IXFR, or ANY queries.
8. Do not persist full query names or client identifiers by default.

## DoT ALPN policy

The client advertises the `dot` ALPN identifier. RFC 7858 and RFC 8310 do not
require a DoT server on its dedicated port to select an ALPN protocol, so an
empty negotiated ALPN is permitted and reported as empty. If a server selects
a non-empty protocol other than `dot`, abort before sending the DNS query.

## Bootstrap transparency

Connecting to a resolver hostname may require an initial DNS lookup. Report
whether the endpoint was reached using a configured bootstrap address, the
system resolver, or an already-known IP. Do not claim that a query avoided the
system resolver when bootstrap used it.

## DNS status and fallback

An HTTP, TLS, or QUIC exchange can succeed while DNS returns `NXDOMAIN`,
`SERVFAIL`, or `REFUSED`. Those are DNS outcomes and must not be converted into
transport errors. Cross-provider or cross-protocol fallback is permitted only
for explicitly classified transport failures and must be disclosed.

## DNSSEC language

The AD bit means the selected recursive resolver reports authenticated data.
It is not proof that this client validated the DNSSEC chain. Use separate
fields for resolver-reported and locally validated DNSSEC state.

## Privacy language

Encrypted transport protects the path between the client and the selected
resolver. The resolver can still observe the query. Provider policy, logging,
filtering, ECS behavior, and jurisdiction remain relevant. See
[RFC 8932](https://www.rfc-editor.org/rfc/rfc8932.html).

ODoH and Anonymized DNSCrypt add relay models but do not justify claims of
absolute anonymity. Their proxy, relay, and target roles must be reported
separately.
