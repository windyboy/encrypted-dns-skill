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

The client advertises the `dot` ALPN identifier and requires the server to
select it. A missing or different ALPN is a hard failure before the DNS query
is sent. This is the repository's strict authentication policy.

## QUIC transport policy

DoQ requires TLS 1.3 and an exact `doq` ALPN selection. DoH3 requires TLS 1.3,
HTTP/3, and an exact `h3` ALPN selection. Certificate, authentication-domain,
SNI, and ALPN failures abort before a DNS query is sent. The initial
implementation does not send 0-RTT data or enable session resumption because
their replay and linkability properties require a separate policy decision.

Each DoQ query uses one client-initiated bidirectional stream, a two-octet
length prefix, DNS Message ID 0, and STREAM FIN. Truncated frames, extra
responses, non-zero response IDs, unexpected streams, and missing FIN are
protocol failures; they never trigger plaintext or cross-protocol fallback.

## DNSCrypt transport policy

Accept only allowlisted DNSCrypt v2 stamps. Validate the stamp type, provider
public key, provider name, resolver certificate signature, validity interval,
and encrypted response. Report the stamp IP bootstrap path, provider
authentication name, certificate serial, and crypto construction. Certificate
or response-authentication failures are hard failures and never trigger
plaintext or cross-protocol fallback. Anonymized DNSCrypt remains unavailable.

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
