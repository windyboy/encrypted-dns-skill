package edns

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestPublicCloudflareDoHInteroperability(t *testing.T) {
	requirePublicInterop(t)
	provider, err := FindProvider("cloudflare")
	if err != nil {
		t.Fatalf("find Cloudflare provider: %v", err)
	}
	wire, query, _, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	wire[0], wire[1] = 0, 0
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	response, info, err := exchangeDoH(ctx, provider, wire, "post", "")
	if err != nil {
		skipIfPublicNetworkUnavailable(t, err)
		t.Fatalf("exchange with public Cloudflare DoH resolver: %v", err)
	}
	if !info.ServerAuthenticated {
		t.Fatal("public Cloudflare DoH resolver was not authenticated")
	}
	if _, err := ParseResponse(response, 0, query); err != nil {
		t.Fatalf("validate public DoH response: %v", err)
	}
}

func TestPublicCloudflareDoTInteroperability(t *testing.T) {
	requirePublicInterop(t)
	provider, err := FindProvider("cloudflare")
	if err != nil {
		t.Fatalf("find Cloudflare provider: %v", err)
	}
	wire, query, transactionID, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	response, info, err := exchangeDoT(ctx, provider, wire, "")
	if err != nil {
		skipIfPublicNetworkUnavailable(t, err)
		t.Fatalf("exchange with public Cloudflare DoT resolver: %v", err)
	}
	if !info.ServerAuthenticated || (info.ALPN != "" && info.ALPN != "dot") {
		t.Fatalf("unexpected public DoT authentication: %#v", info)
	}
	if _, err := ParseResponse(response, transactionID, query); err != nil {
		t.Fatalf("validate public DoT response: %v", err)
	}
}

func requirePublicInterop(t *testing.T) {
	t.Helper()
	if os.Getenv("EDNSDIAG_PUBLIC_INTEROP") != "1" {
		t.Skip("set EDNSDIAG_PUBLIC_INTEROP=1 to run public DoH/DoT interoperability tests")
	}
}

func skipIfPublicNetworkUnavailable(t *testing.T, err error) {
	t.Helper()
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		t.Skipf("public network unavailable: %v", err)
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) && (operationError.Op == "dial" || operationError.Timeout()) {
		t.Skipf("public network unavailable: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ECONNREFUSED) {
		t.Skipf("public network unavailable: %v", err)
	}
}
