package edns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ameshkov/dnsstamps"
)

type UnsupportedError struct {
	Message string
}

func (err *UnsupportedError) Error() string { return err.Message }

func IsUnsupported(err error) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported)
}

type Provider struct {
	ID           string
	Profile      string
	SourceURL    string
	VerifiedDate string
	DoHURL       string
	DoTAddr      string
	DoTName      string
	DoQAddr      string
	DoQName      string
	DoH3URL      string
	DNSCrypt     DNSCryptConfig
}

// DNSCryptConfig is public resolver metadata, not a credential. DNSCrypt
// stamps encode these fields as a portable connection descriptor.
type DNSCryptConfig struct {
	ServerAddress string
	ProviderName  string
	PublicKey     [32]byte
	Properties    dnsstamps.ServerInformalProperties
}

func (config DNSCryptConfig) Stamp() (string, error) {
	if config.ServerAddress == "" || config.ProviderName == "" {
		return "", fmt.Errorf("DNSCrypt address and provider name are required")
	}
	if config.PublicKey == [32]byte{} {
		return "", fmt.Errorf("DNSCrypt public key is required")
	}
	stamp := dnsstamps.ServerStamp{
		ServerAddrStr: config.ServerAddress,
		ServerPk:      config.PublicKey[:],
		ProviderName:  config.ProviderName,
		Props:         config.Properties,
		Proto:         dnsstamps.StampProtoTypeDNSCrypt,
	}
	return stamp.String(), nil
}

var providers = map[string]Provider{
	"cloudflare": {
		ID:           "cloudflare",
		Profile:      "unfiltered",
		SourceURL:    "https://developers.cloudflare.com/1.1.1.1/encryption/",
		VerifiedDate: "2026-08-13",
		DoHURL:       "https://cloudflare-dns.com/dns-query",
		DoTAddr:      "one.one.one.one:853",
		DoTName:      "one.one.one.one",
		DoH3URL:      "https://cloudflare-dns.com/dns-query",
	},
	"google": {
		ID:           "google",
		Profile:      "unfiltered",
		SourceURL:    "https://developers.google.com/speed/public-dns/docs/secure-transports",
		VerifiedDate: "2026-08-13",
		DoHURL:       "https://dns.google/dns-query",
		DoTAddr:      "dns.google:853",
		DoTName:      "dns.google",
		DoH3URL:      "https://dns.google/dns-query",
	},
	"quad9": {
		ID:           "quad9",
		Profile:      "security-filtered",
		SourceURL:    "https://docs.quad9.net/services/",
		VerifiedDate: "2026-08-13",
		DoHURL:       "https://dns.quad9.net/dns-query",
		DoTAddr:      "dns.quad9.net:853",
		DoTName:      "dns.quad9.net",
	},
	"adguard": {
		ID:           "adguard",
		Profile:      "ad-and-security-filtered",
		SourceURL:    "https://adguard-dns.io/kb/en/general/dns-providers/",
		VerifiedDate: "2026-08-14",
		DoHURL:       "https://dns.adguard-dns.com/dns-query",
		DoTAddr:      "dns.adguard-dns.com:853",
		DoTName:      "dns.adguard-dns.com",
		DoQAddr:      "dns.adguard-dns.com:853",
		DoQName:      "dns.adguard-dns.com",
		DNSCrypt: DNSCryptConfig{
			ServerAddress: "94.140.14.14:5443",
			ProviderName:  "2.dnscrypt.default.ns1.adguard.com",
			PublicKey: [32]byte{
				0xd1, 0x2b, 0x47, 0xf2, 0x52, 0xdc, 0xf2, 0xc2,
				0xbb, 0xf8, 0x99, 0x10, 0x86, 0xea, 0xf7, 0x9c,
				0xe4, 0x49, 0x5d, 0x8b, 0x16, 0xc8, 0xa0, 0xc4,
				0x32, 0x2e, 0x52, 0xca, 0x3f, 0x39, 0x08, 0x73,
			},
			Properties: dnsstamps.ServerInformalPropertyDNSSEC | dnsstamps.ServerInformalPropertyNoLog,
		},
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
		if provider.DNSCrypt != (DNSCryptConfig{}) {
			var err error
			endpoint, err = provider.DNSCrypt.Stamp()
			if err != nil {
				return "", fmt.Errorf("provider %q has invalid DNSCrypt metadata: %w", provider.ID, err)
			}
		}
	default:
		return "", &UnsupportedError{Message: fmt.Sprintf("protocol %q is not available", protocol)}
	}
	if endpoint == "" {
		return "", &UnsupportedError{Message: fmt.Sprintf("provider %q does not support protocol %q", provider.ID, protocol)}
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
