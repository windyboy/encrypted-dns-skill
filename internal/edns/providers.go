package edns

import (
	"fmt"
	"strings"
)

type Provider struct {
	ID       string
	Profile  string
	DoHURL   string
	DoTAddr  string
	DoTName  string
}

var providers = map[string]Provider{
	"cloudflare": {
		ID:      "cloudflare",
		Profile: "unfiltered",
		DoHURL:  "https://cloudflare-dns.com/dns-query",
		DoTAddr: "one.one.one.one:853",
		DoTName: "one.one.one.one",
	},
	"google": {
		ID:      "google",
		Profile: "unfiltered",
		DoHURL:  "https://dns.google/dns-query",
		DoTAddr: "dns.google:853",
		DoTName: "dns.google",
	},
	"quad9": {
		ID:      "quad9",
		Profile: "security-filtered",
		DoHURL:  "https://dns.quad9.net/dns-query",
		DoTAddr: "dns.quad9.net:853",
		DoTName: "dns.quad9.net",
	},
	"adguard": {
		ID:      "adguard",
		Profile: "ad-and-security-filtered",
		DoHURL:  "https://dns.adguard-dns.com/dns-query",
		DoTAddr: "dns.adguard-dns.com:853",
		DoTName: "dns.adguard-dns.com",
	},
}

func FindProvider(name string) (Provider, error) {
	provider, ok := providers[strings.ToLower(name)]
	if !ok {
		return Provider{}, fmt.Errorf("unknown provider %q", name)
	}
	return provider, nil
}
