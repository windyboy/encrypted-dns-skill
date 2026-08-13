package edns

import "testing"

func TestBuiltInProvidersHaveStrictEndpoints(t *testing.T) {
	for _, name := range []string{"cloudflare", "google", "quad9", "adguard"} {
		provider, err := FindProvider(name)
		if err != nil {
			t.Fatalf("find provider %s: %v", name, err)
		}
		if provider.DoHURL == "" || provider.DoTAddr == "" || provider.DoTName == "" {
			t.Fatalf("provider %s is incomplete: %#v", name, provider)
		}
	}
	if _, err := FindProvider("custom"); err == nil {
		t.Fatal("unapproved custom provider was accepted")
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
		{provider: "cloudflare", protocol: "doq", allowed: false},
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
