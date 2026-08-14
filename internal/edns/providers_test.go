package edns

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/ameshkov/dnsstamps"
)

func TestBuiltInProvidersHaveStrictEndpoints(t *testing.T) {
	for _, name := range []string{"cloudflare", "google", "quad9", "adguard"} {
		provider, err := FindProvider(name)
		if err != nil {
			t.Fatalf("find provider %s: %v", name, err)
		}
		if provider.DoHURL == "" || provider.DoTAddr == "" || provider.DoTName == "" {
			t.Fatalf("provider %s is incomplete: %#v", name, provider)
		}
		source, err := url.ParseRequestURI(provider.SourceURL)
		if err != nil || source.Scheme != "https" || source.Host == "" {
			t.Fatalf("provider %s has invalid official source URL %q: %v", name, provider.SourceURL, err)
		}
		if _, err := time.Parse(time.DateOnly, provider.VerifiedDate); err != nil {
			t.Fatalf("provider %s has invalid verification date %q: %v", name, provider.VerifiedDate, err)
		}
	}
	if _, err := FindProvider("custom"); err == nil {
		t.Fatal("unapproved custom provider was accepted")
	}
}

func TestAdGuardDNSCryptMetadataGeneratesValidStamp(t *testing.T) {
	provider, err := FindProvider("adguard")
	if err != nil {
		t.Fatalf("find AdGuard provider: %v", err)
	}
	if provider.DNSCrypt == (DNSCryptConfig{}) {
		t.Fatal("AdGuard DNSCrypt metadata is missing")
	}
	encoded, err := provider.Endpoint("dnscrypt")
	if err != nil {
		t.Fatalf("generate DNSCrypt stamp: %v", err)
	}
	stamp, err := dnsstamps.NewServerStampFromString(encoded)
	if err != nil {
		t.Fatalf("parse generated DNSCrypt stamp: %v", err)
	}
	if stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt ||
		stamp.ServerAddrStr != provider.DNSCrypt.ServerAddress ||
		stamp.ProviderName != provider.DNSCrypt.ProviderName ||
		stamp.Props != provider.DNSCrypt.Properties ||
		!bytes.Equal(stamp.ServerPk, provider.DNSCrypt.PublicKey[:]) {
		t.Fatalf("generated stamp does not preserve public metadata: %#v", stamp)
	}
}

func TestDNSCryptMetadataRejectsIncompleteConfiguration(t *testing.T) {
	validKey := [32]byte{1}
	tests := []struct {
		name   string
		config DNSCryptConfig
	}{
		{name: "missing address", config: DNSCryptConfig{ProviderName: "2.example", PublicKey: validKey}},
		{name: "missing provider name", config: DNSCryptConfig{ServerAddress: "192.0.2.1:443", PublicKey: validKey}},
		{name: "missing public key", config: DNSCryptConfig{ServerAddress: "192.0.2.1:443", ProviderName: "2.example"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.config.Stamp(); err == nil {
				t.Fatal("incomplete DNSCrypt metadata was accepted")
			}
		})
	}
}

func TestProviderProtocolMatrix(t *testing.T) {
	tests := []struct {
		provider string
		protocol string
		allowed  bool
	}{
		{provider: "cloudflare", protocol: "doh3", allowed: true},
		{provider: "google", protocol: "doh3", allowed: true},
		{provider: "adguard", protocol: "doq", allowed: true},
		{provider: "adguard", protocol: "dnscrypt", allowed: true},
		{provider: "cloudflare", protocol: "doq", allowed: false},
		{provider: "cloudflare", protocol: "dnscrypt", allowed: false},
		{provider: "quad9", protocol: "doh3", allowed: false},
		{provider: "adguard", protocol: "doh3", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.provider+"/"+test.protocol, func(t *testing.T) {
			provider, err := FindProvider(test.provider)
			if err != nil {
				t.Fatalf("find provider: %v", err)
			}
			_, err = provider.Endpoint(test.protocol)
			if test.allowed && err != nil {
				t.Fatalf("supported endpoint rejected: %v", err)
			}
			if !test.allowed && err == nil {
				t.Fatal("unsupported endpoint was inferred")
			}
		})
	}
}
