# Built-in provider policy

Provider endpoints and capabilities must be verified against the provider's
official documentation before they are added or changed. The built-in entries
below were verified on 2026-08-13.

## Candidate providers

| Provider | DoH endpoint | DoT endpoint / authentication name | Official documentation | Profile |
| --- | --- | --- | --- | --- |
| Cloudflare | `https://cloudflare-dns.com/dns-query` | `one.one.one.one:853` | [DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/) / [DoT](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/) | Unfiltered |
| Google | `https://dns.google/dns-query` | `dns.google:853` | [DoH](https://developers.google.com/speed/public-dns/docs/doh) / [DoT](https://developers.google.com/speed/public-dns/docs/dns-over-tls) | Unfiltered |
| Quad9 | `https://dns.quad9.net/dns-query` | `dns.quad9.net:853` | [Quad9 services](https://docs.quad9.net/services/) | Security filtered; HTTP/2 required |
| AdGuard | `https://dns.adguard-dns.com/dns-query` | `dns.adguard-dns.com:853` | [AdGuard providers](https://adguard-dns.io/kb/general/dns-providers/) | Ads, tracking, and security filtered |

## Registry requirements

Each built-in provider entry must include:

- stable provider identifier;
- protocol and endpoint;
- authentication domain name;
- bootstrap addresses only when officially published;
- filtering/ECS profile;
- official source URL;
- last verification date.

Do not infer one protocol endpoint from another. Do not treat filtering and
non-filtering services as interchangeable. Provider comparison results must
remain separate.
