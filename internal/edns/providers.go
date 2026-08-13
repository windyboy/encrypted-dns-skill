package edns

import (
	"fmt"
	"strings"
)

type Provider struct {
	ID            string
	Profile       string
	DoHURL        string
	DoTAddr       string
	DoTName       string
	DoQAddr       string
	DoQName       string
	DoH3URL       string
	DNSCryptStamp string
}

var providers = map[string]Provider{
	"cloudflare": {
		ID:      "cloudflare",
		Profile: "unfiltered",
		DoHURL:  "https://cloudflare-dns.com/dns-query",
		DoTAddr: "one.one.one.one:853",
		DoTName: "one.one.one.one",
		DoH3URL: "https://cloudflare-dns.com/dns-query",
	},
	"google": {
		ID:      "google",
		Profile: "unfiltered",
		DoHURL:  "https://dns.google/dns-query",
		DoTAddr: "dns.google:853",
		DoTName: "dns.google",
		DoH3URL: "https://dns.google/dns-query",
	},
	"quad9": {
		ID:      "quad9",
		Profile: "security-filtered",
		DoHURL:  "https://dns.quad9.net/dns-query",
		DoTAddr: "dns.quad9.net:853",
		DoTName: "dns.quad9.net",
	},
	"adguard": {
		ID:            "adguard",
		Profile:       "ad-and-security-filtered",
		DoHURL:        "https://dns.adguard-dns.com/dns-query",
		DoTAddr:       "dns.adguard-dns.com:853",
		DoTName:       "dns.adguard-dns.com",
		DoQAddr:       "dns.adguard-dns.com:853",
		DoQName:       "dns.adguard-dns.com",
		DNSCryptStamp: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	},
}

func (provider Provider) Endpoint(protocol string) (string, error) {
	var endpoint string
	switch strings.ToLower(protocol) {
	case "doh":
		endpoint = provider.DoHURL
	case "dot":
		endpoint = provider.DoTAddr
	case "doq":
		endpoint = provider.DoQAddr
	case "doh3":
		endpoint = provider.DoH3URL
	case "dnscrypt":
		endpoint = provider.DNSCryptStamp
	default:
		return "", fmt.Errorf("protocol %q is not available", protocol)
	}
	if endpoint == "" {
		return "", fmt.Errorf("provider %q does not support protocol %q", provider.ID, protocol)
	}
	return endpoint, nil
}

func FindProvider(name string) (Provider, error) {
	provider, ok := providers[strings.ToLower(name)]
	if !ok {
		return Provider{}, fmt.Errorf("unknown provider %q", name)
	}
	return provider, nil
}
