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
