package edns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

type dnsCryptHandlerFunc func(dnscrypt.ResponseWriter, *dns.Msg) error

func (handler dnsCryptHandlerFunc) ServeDNS(writer dnscrypt.ResponseWriter, request *dns.Msg) error {
	return handler(writer, request)
}

func TestExchangeDNSCrypt(t *testing.T) {
	config, err := dnscrypt.GenerateResolverConfig("resolver.test", nil)
	if err != nil {
		t.Fatalf("generate DNSCrypt resolver config: %v", err)
	}
	config.EsVersion = dnscrypt.XChacha20Poly1305
	cert, err := config.CreateCert()
	if err != nil {
		t.Fatalf("create DNSCrypt certificate: %v", err)
	}
	server := &dnscrypt.Server{
		ProviderName: config.ProviderName,
		ResolverCert: cert,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Handler: dnsCryptHandlerFunc(func(writer dnscrypt.ResponseWriter, request *dns.Msg) error {
			response := new(dns.Msg)
			response.SetRcode(request, dns.RcodeNameError)
			return writer.WriteMsg(response)
		}),
	}
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for DNSCrypt: %v", err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	})
	go func() { _ = server.ServeUDP(connection) }()
	stamp, err := config.CreateStamp(connection.LocalAddr().String())
	if err != nil {
		t.Fatalf("create DNSCrypt stamp: %v", err)
	}

	wire, query, transactionID, err := BuildQuery("missing.example", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	response, info, peer, err := exchangeDNSCrypt(t.Context(), stamp.String(), wire)
	if err != nil {
		t.Fatalf("exchange DNSCrypt: %v", err)
	}
	if !info.ServerAuthenticated || info.Bootstrap != "stamp_ip" || info.CryptoConstruction != "XChacha20Poly1305" {
		t.Fatalf("unexpected transport info: %#v", info)
	}
	if peer.ProviderName != config.ProviderName || peer.ServerAddress != connection.LocalAddr().String() || peer.CertificateSerial == 0 {
		t.Fatalf("unexpected peer info: %#v", peer)
	}
	dnsResult, err := ParseResponse(response, transactionID, query)
	if err != nil {
		t.Fatalf("parse DNSCrypt response: %v", err)
	}
	if dnsResult.RCode != "NXDOMAIN" {
		t.Fatalf("rcode = %q, want NXDOMAIN", dnsResult.RCode)
	}
}

func TestExchangeDNSCryptRejectsInvalidStamp(t *testing.T) {
	wire, _, _, _ := BuildQuery("example.com", "A")
	_, info, _, err := exchangeDNSCrypt(t.Context(), "sdns://not-a-valid-stamp", wire)
	if err == nil || !strings.Contains(err.Error(), "authenticate DNSCrypt resolver") {
		t.Fatalf("error = %v, want invalid stamp authentication error", err)
	}
	if info.ServerAuthenticated {
		t.Fatal("invalid stamp authenticated a resolver")
	}
}

func TestExchangeDNSCryptRejectsExpiredCertificate(t *testing.T) {
	config, certBytes := newSerializedDNSCryptCert(t)
	now := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(certBytes[116:120], now-120)
	binary.BigEndian.PutUint32(certBytes[120:124], now-60)
	stamp := startDNSCryptTestEndpoint(t, config, certBytes, nil)
	wire, _, _, _ := BuildQuery("example.com", "A")
	_, info, _, err := exchangeDNSCrypt(t.Context(), stamp, wire)
	if err == nil || !strings.Contains(err.Error(), "invalid ts-start or ts-end") {
		t.Fatalf("error = %v, want expired certificate error", err)
	}
	if info.ServerAuthenticated {
		t.Fatal("expired certificate authenticated a resolver")
	}
}

func TestExchangeDNSCryptRejectsInvalidCertificateSignature(t *testing.T) {
	config, certBytes := newSerializedDNSCryptCert(t)
	certBytes[8] ^= 0xff
	stamp := startDNSCryptTestEndpoint(t, config, certBytes, nil)
	wire, _, _, _ := BuildQuery("example.com", "A")
	_, info, _, err := exchangeDNSCrypt(t.Context(), stamp, wire)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error = %v, want invalid certificate signature error", err)
	}
	if info.ServerAuthenticated {
		t.Fatal("invalid certificate signature authenticated a resolver")
	}
}

func TestExchangeDNSCryptRejectsMalformedEncryptedResponse(t *testing.T) {
	config, certBytes := newSerializedDNSCryptCert(t)
	stamp := startDNSCryptTestEndpoint(t, config, certBytes, []byte{1, 2, 3})
	wire, _, _, _ := BuildQuery("example.com", "A")
	_, info, _, err := exchangeDNSCrypt(t.Context(), stamp, wire)
	if err == nil || !strings.Contains(err.Error(), "exchange DNSCrypt query") {
		t.Fatalf("error = %v, want malformed response error", err)
	}
	if !info.ServerAuthenticated {
		t.Fatal("valid certificate was not authenticated before malformed response")
	}
}

func TestExchangeDNSCryptTimesOut(t *testing.T) {
	config, certBytes := newSerializedDNSCryptCert(t)
	stamp := startDNSCryptTestEndpoint(t, config, certBytes, []byte{})
	wire, _, _, _ := BuildQuery("example.com", "A")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, info, _, err := exchangeDNSCrypt(ctx, stamp, wire)
	if err == nil {
		t.Fatal("DNSCrypt timeout was accepted")
	}
	if !info.ServerAuthenticated {
		t.Fatal("timeout test did not complete certificate authentication")
	}
}

func TestDNSCryptAdGuardInteroperability(t *testing.T) {
	if os.Getenv("EDNSDIAG_DNSCRYPT_INTEROP") != "1" {
		t.Skip("set EDNSDIAG_DNSCRYPT_INTEROP=1 to run the public DNSCrypt interoperability test")
	}
	provider, err := FindProvider("adguard")
	if err != nil {
		t.Fatalf("find AdGuard provider: %v", err)
	}
	wire, query, transactionID, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	response, info, peer, err := exchangeDNSCrypt(ctx, provider.DNSCryptStamp, wire)
	if err != nil {
		t.Fatalf("exchange with public AdGuard DNSCrypt resolver: %v", err)
	}
	if !info.ServerAuthenticated || peer.ProviderName != "2.dnscrypt.default.ns1.adguard.com" || peer.ServerAddress != "94.140.14.14:5443" {
		t.Fatalf("unexpected public resolver identity: transport=%#v peer=%#v", info, peer)
	}
	if _, err := ParseResponse(response, transactionID, query); err != nil {
		t.Fatalf("validate public DNSCrypt response: %v", err)
	}
}

func newSerializedDNSCryptCert(t *testing.T) (dnscrypt.ResolverConfig, []byte) {
	t.Helper()
	config, err := dnscrypt.GenerateResolverConfig("resolver.test", nil)
	if err != nil {
		t.Fatalf("generate DNSCrypt resolver config: %v", err)
	}
	cert, err := config.CreateCert()
	if err != nil {
		t.Fatalf("create DNSCrypt certificate: %v", err)
	}
	certBytes, err := cert.Serialize()
	if err != nil {
		t.Fatalf("serialize DNSCrypt certificate: %v", err)
	}
	return config, certBytes
}

func startDNSCryptTestEndpoint(t *testing.T, config dnscrypt.ResolverConfig, certBytes, encryptedResponse []byte) string {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen for DNSCrypt test endpoint: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	stamp, err := config.CreateStamp(connection.LocalAddr().String())
	if err != nil {
		t.Fatalf("create DNSCrypt stamp: %v", err)
	}
	go func() {
		buffer := make([]byte, 4096)
		count, client, readErr := connection.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		var request dns.Msg
		if request.Unpack(buffer[:count]) != nil {
			return
		}
		reply := new(dns.Msg)
		reply.SetReply(&request)
		reply.Authoritative = true
		reply.RecursionAvailable = true
		reply.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{packDNSCryptTXT(certBytes)},
		}}
		packed, packErr := reply.Pack()
		if packErr != nil {
			return
		}
		if _, writeErr := connection.WriteToUDP(packed, client); writeErr != nil {
			return
		}
		_, client, readErr = connection.ReadFromUDP(buffer)
		if readErr == nil && encryptedResponse != nil && len(encryptedResponse) > 0 {
			_, _ = connection.WriteToUDP(encryptedResponse, client)
		}
	}()
	return stamp.String()
}

func packDNSCryptTXT(buffer []byte) string {
	var output strings.Builder
	for _, value := range buffer {
		switch {
		case value == '"' || value == '\\':
			output.WriteByte('\\')
			output.WriteByte(value)
		case value < ' ' || value > '~':
			fmt.Fprintf(&output, "\\%03d", value)
		default:
			output.WriteByte(value)
		}
	}
	return output.String()
}
