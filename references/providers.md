# Built-in provider policy

Provider endpoints and capabilities must be verified against the provider's
official documentation before they are added or changed. Record the
verification date in the implementation change.

## Candidate providers

| Provider | Official documentation | Notes |
| --- | --- | --- |
| Cloudflare | [1.1.1.1 DoH API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/) | Use RFC 8484 wire format for the core client |
| Google | [Google Public DNS DoH](https://developers.google.com/speed/public-dns/docs/doh) | Distinguish `/dns-query` wire format from `/resolve` JSON |
| Quad9 | [Quad9 services](https://docs.quad9.net/services/) | Filtering can affect NXDOMAIN semantics; DoH requires a standards-capable client |
| AdGuard | [AdGuard public DNS servers](https://adguard-dns.io/en/public-dns/servers.html) | Supports multiple encrypted transports and filtering profiles |

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
