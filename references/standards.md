# Standards and authoritative sources

Verified on 2026-08-13. Protocol behavior must be based on the published
standard, not on summaries or provider-specific JSON APIs.

| Capability | Authority | Project scope |
| --- | --- | --- |
| Agent Skills package | [Agent Skills specification](https://agentskills.io/specification) | Required package format |
| OMP discovery | [OMP Skills documentation](https://github.com/can1357/oh-my-pi/blob/main/docs/skills.md) | Supported host |
| DoH | [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) | Planned |
| DoT | [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) | Planned |
| DoT authentication profiles | [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310.html) | Strict privacy only |
| DoQ | [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) | Planned |
| ODoH | [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html) | Research until a maintained implementation is selected |
| DNS privacy operations | [RFC 8932](https://www.rfc-editor.org/rfc/rfc8932.html) | Security and privacy guidance |
| EDNS(0) padding | [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830.html) and [RFC 8467](https://www.rfc-editor.org/rfc/rfc8467.html) | Evaluate per transport |
| DNSCrypt | [DNSCrypt protocol specification](https://github.com/DNSCrypt/dnscrypt-protocol) | Planned, non-IETF |
| Anonymized DNSCrypt | [Anonymized DNSCrypt specification](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt) | Research |
| Go transport engine | [AdGuard dnsproxy upstream package](https://pkg.go.dev/github.com/AdguardTeam/dnsproxy/upstream) | Candidate dependency; pin a release |

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
