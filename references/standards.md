# Standards and authoritative sources

Verified on 2026-08-13. Protocol behavior must be based on the published
standard, not on summaries or provider-specific JSON APIs.

| Capability | Authority | Project scope |
| --- | --- | --- |
| Agent Skills package | [Agent Skills specification](https://agentskills.io/specification) | Required package format |
| OMP discovery | [OMP Skills documentation](https://github.com/can1357/oh-my-pi/blob/main/docs/skills.md) | Supported host |
| DoH | [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) | Implemented over HTTP/1.1 and HTTP/2 |
| DoH3 | [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) over [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html) | Implemented |
| DoT | [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) | Implemented |
| DoT authentication profiles | [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310.html) | Strict privacy only |
| DoQ | [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) | Implemented for single-response queries |
| ODoH | [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html) | Research until a maintained implementation is selected |
| DNS privacy operations | [RFC 8932](https://www.rfc-editor.org/rfc/rfc8932.html) | Security and privacy guidance |
| EDNS(0) padding | [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830.html) and [RFC 8467](https://www.rfc-editor.org/rfc/rfc8467.html) | Evaluate per transport |
| DNSCrypt | [DNSCrypt protocol specification](https://github.com/DNSCrypt/dnscrypt-protocol) | Planned, non-IETF |
| Anonymized DNSCrypt | [Anonymized DNSCrypt specification](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt) | Research |
| Go DNS wire and IDNA support | [Go x/net module](https://pkg.go.dev/golang.org/x/net) | Pinned to v0.58.0; use `dnsmessage` and `idna` |
| Go QUIC and HTTP/3 support | [quic-go documentation](https://quic-go.net/docs/) | Pinned to v0.61.0 |

## Deliberate exclusions

- DNS-over-DTLS ([RFC 8094](https://www.rfc-editor.org/rfc/rfc8094.html))
  is experimental and is not a target transport.
- DNS zone transfer over TLS
  ([RFC 9103](https://www.rfc-editor.org/rfc/rfc9103.html)) is outside the
  client-to-recursive diagnostic scope.
- Recursive-to-authoritative encryption and resolver/server operation are
  outside the initial scope.

## Terminology

DoH3 means RFC 8484 semantics carried over HTTP/3. It is not a separate DNS
message format. DNSCrypt is an encrypted DNS protocol with its own
specification; do not label it as an IETF RFC.

For DoH, accept and send `application/dns-message`. Keep HTTP status separate
from the DNS RCODE: a valid NXDOMAIN or SERVFAIL response still uses HTTP 2xx.
For DoT, use the strict privacy profile and verify both the PKIX chain and the
configured authentication domain name.

For DoQ, use ALPN `doq`, UDP port 853, a separate client-initiated bidirectional
stream per query, the two-octet DNS-over-TCP length field, STREAM FIN, and DNS
Message ID 0. DoH3 retains RFC 8484 message and HTTP semantics and requires
HTTP/3 with ALPN `h3`.
