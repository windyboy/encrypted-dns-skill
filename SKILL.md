---
name: encrypted-dns-skill
description: Query, probe, and compare DNS resolution through supported encrypted transports. Use for encrypted DNS record lookups, resolver connectivity tests, TLS and QUIC diagnostics, protocol comparisons, DNSSEC status inspection, and troubleshooting DoH, DoT, DoQ, DoH3, or DNSCrypt resolver endpoints.
---

# Encrypted DNS Diagnostics

Use `ednsdiag` for encrypted DNS work. Do not assemble protocol requests with
`curl`, `openssl`, or ad-hoc scripts when `ednsdiag` supports the operation.
The executable requires network access.

Prefer an installed `ednsdiag` executable. When it is unavailable and Go 1.26+
is installed, run the source from the skill root with:

```bash
go run ./cmd/ednsdiag <command> [arguments]
```

Do not download or execute an unverified binary automatically. Building from
source may require permission to download pinned Go modules.

## Check capabilities

Before attempting an operation, run:

```bash
ednsdiag capabilities
```

Only use a protocol when its reported status is `available`. Never describe a
`planned` or `experimental` capability as implemented.

## Commands

```bash
ednsdiag query example.com A --protocol doh --provider cloudflare
ednsdiag query gmail.com MX --protocol dot --provider google --timeout 5s
ednsdiag query example.com AAAA --protocol doq --provider adguard
ednsdiag query example.com HTTPS --protocol doh3 --provider cloudflare
ednsdiag capabilities
ednsdiag version
```

Use `--method get` or `--method post` only with DoH or DoH3. The default is POST.
Built-in providers are `cloudflare`, `google`, `quad9`, and `adguard`. Provider
protocol support and filtering policies differ and are included in the result.
Run `capabilities` and do not infer an unsupported endpoint. `probe` and
`compare` remain reserved until their capabilities are implemented.

## Required behavior

- Use standard DNS wire messages for DoH, not provider-specific JSON APIs.
- Apply strict certificate and authentication-domain validation.
- Never silently downgrade to plaintext DNS.
- Do not retry `NXDOMAIN`, `NODATA`, `SERVFAIL`, or `REFUSED` through another
  protocol as though they were transport failures.
- Keep results from different providers and protocols separate.
- Report every fallback attempt and its reason.
- Treat the DNS `AD` bit as validation reported by the selected resolver, not
  as local DNSSEC validation.
- Do not connect to addresses returned in DNS answers.

## Result interpretation

- `completed: true` means a protocol exchange completed. It does not imply
  `NOERROR`.
- Read `dns.rcode` for the DNS outcome.
- Read `transport.server_authenticated` separately from DNSSEC fields.
- Read `transport.bootstrap`; `system_resolver` means resolving the encrypted
  resolver endpoint itself used the operating system resolver.
- Empty answers with `NOERROR` represent NODATA.
- A filtering resolver may synthesize `NXDOMAIN`; disclose the provider.

## References

- Read [references/standards.md](references/standards.md) before changing
  protocol behavior.
- Read [references/security.md](references/security.md) before changing TLS,
  bootstrap, fallback, endpoint, or privacy behavior.
- Read [references/providers.md](references/providers.md) before adding or
  modifying a built-in provider.
- Keep output compatible with
  [schemas/result-v1.schema.json](schemas/result-v1.schema.json).

## Scope

The target scope is widely deployed client-to-recursive encrypted DNS:
DoH, DoT, DoQ, DoH3, and DNSCrypt. ODoH and Anonymized DNSCrypt remain
research capabilities until explicitly marked available.

Do not use this skill for DNS-over-DTLS, zone transfers, authoritative-server
operation, changing hosted DNS records, or replacing the operating system's
stub resolver.
