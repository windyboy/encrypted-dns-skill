# Built-in provider policy

Provider endpoints and capabilities must be verified against the provider's
official documentation before they are added or changed. AdGuard was most
recently re-verified on 2026-08-14; the other entries were verified on
2026-08-13. The runtime registry is authoritative for per-provider dates.

## Candidate providers

| Provider | DoH endpoint | DoT endpoint / authentication name | QUIC support | DNSCrypt | Official documentation | Profile |
| --- | --- | --- | --- | --- | --- | --- |
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `one.one.one.one:853` | DoH3 at the DoH endpoint | No verified built-in stamp | [DoH and HTTP/3](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/) / [DoT](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/) | Unfiltered |
| Google | `https://dns.google/dns-query` | `dns.google:853` | DoH3 at the DoH endpoint | No verified built-in stamp | [Secure transports](https://developers.google.com/speed/public-dns/docs/secure-transports) | Unfiltered |
| Quad9 | `https://dns.quad9.net/dns-query` | `dns.quad9.net:853` | Not enabled without an official endpoint statement | No verified built-in stamp | [Quad9 services](https://docs.quad9.net/services/) | Security filtered; HTTP/2 required |
| AdGuard | `https://dns.adguard-dns.com/dns-query` | `dns.adguard-dns.com:853` | DoQ at `dns.adguard-dns.com:853` | Runtime-generated stamp for `2.dnscrypt.default.ns1.adguard.com` at `94.140.14.14:5443` | [Known DNS providers](https://adguard-dns.io/kb/en/general/dns-providers/) / [DNSCrypt public resolver registry](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/public-resolvers.md) | Ads, tracking, and security filtered |

## Registry requirements

Each built-in provider entry must include:

- stable provider identifier;
- protocol and endpoint;
- authentication domain name;
- bootstrap addresses only when officially published;
- filtering/ECS profile;
- official source URL;
- last verification date.

The runtime `Provider` registry stores the official source URL and verification
date alongside each endpoint. Update both fields whenever an endpoint or
capability is re-verified; the markdown table alone is not authoritative for
runtime metadata.

DNSCrypt entries store the public resolver address, provider name, Ed25519
public key bytes, and advertised properties as typed metadata. The runtime
generates the standard `sdns://` connection descriptor with the pinned
`dnsstamps` package. These fields are public authentication metadata, not
credentials.

Do not infer one protocol endpoint from another. Do not treat filtering and
non-filtering services as interchangeable. Provider comparison results must
remain separate.
