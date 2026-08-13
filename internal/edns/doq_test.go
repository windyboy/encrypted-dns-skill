package edns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

func TestExchangeDoQ(t *testing.T) {
	listener, roots := newDoQTestListener(t, "doq")
	defer listener.Close()

	serverError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(t.Context())
		if err != nil {
			serverError <- err
			return
		}
		defer connection.CloseWithError(doqNoError, "")
		stream, err := connection.AcceptStream(t.Context())
		if err != nil {
			serverError <- err
			return
		}
		wire, err := readDNSFrame(stream)
		if err != nil {
			serverError <- err
			return
		}
		if binary.BigEndian.Uint16(wire[:2]) != 0 {
			serverError <- fmt.Errorf("DoQ query ID is not zero")
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(wire); err != nil {
			serverError <- err
			return
		}
		response, err := (dnsmessage.Message{
			Header:    dnsmessage.Header{ID: 0, Response: true, RCode: dnsmessage.RCodeNameError},
			Questions: query.Questions,
		}).Pack()
		if err == nil {
			err = writeDNSFrame(stream, response)
		}
		if err == nil {
			err = stream.Close()
		}
		serverError <- err
	}()

	wire, query, _, err := BuildQuery("missing.example", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	binary.BigEndian.PutUint16(wire[:2], 0)
	response, info, err := exchangeDoQWithConfig(t.Context(), Provider{
		DoQAddr: listener.Addr().String(),
		DoQName: "resolver.test",
	}, wire, &tls.Config{RootCAs: roots}, &quic.Config{})
	if err != nil {
		t.Fatalf("exchange DoQ: %v", err)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("serve DoQ: %v", err)
	}
	if !info.ServerAuthenticated || info.ALPN != "doq" || info.QUICVersion == "" || info.TLSVersion != "TLS1.3" {
		t.Fatalf("unexpected transport info: %#v", info)
	}
	dnsResult, err := ParseResponse(response, 0, query)
	if err != nil {
		t.Fatalf("parse DoQ response: %v", err)
	}
	if dnsResult.RCode != "NXDOMAIN" {
		t.Fatalf("rcode = %q, want NXDOMAIN", dnsResult.RCode)
	}
}

func TestExchangeDoQRejectsMalformedFrame(t *testing.T) {
	listener, roots := newDoQTestListener(t, "doq")
	defer listener.Close()
	go func() {
		connection, err := listener.Accept(t.Context())
		if err != nil {
			return
		}
		defer connection.CloseWithError(doqNoError, "")
		stream, err := connection.AcceptStream(t.Context())
		if err != nil {
			return
		}
		_, _ = readDNSFrame(stream)
		_, _ = stream.Write([]byte{0, 20, 1})
		_ = stream.Close()
	}()

	wire, _, _, _ := BuildQuery("example.com", "A")
	binary.BigEndian.PutUint16(wire[:2], 0)
	_, _, err := exchangeDoQWithConfig(t.Context(), Provider{DoQAddr: listener.Addr().String(), DoQName: "resolver.test"}, wire, &tls.Config{RootCAs: roots}, &quic.Config{})
	if err == nil || !strings.Contains(err.Error(), "read DNS response") {
		t.Fatalf("error = %v, want malformed frame error", err)
	}
}

func TestExchangeDoQTimesOut(t *testing.T) {
	listener, roots := newDoQTestListener(t, "doq")
	defer listener.Close()
	go func() {
		connection, err := listener.Accept(t.Context())
		if err != nil {
			return
		}
		defer connection.CloseWithError(doqNoError, "")
		stream, err := connection.AcceptStream(t.Context())
		if err != nil {
			return
		}
		_, _ = readDNSFrame(stream)
		<-stream.Context().Done()
	}()

	wire, _, _, _ := BuildQuery("example.com", "A")
	binary.BigEndian.PutUint16(wire[:2], 0)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := exchangeDoQWithConfig(ctx, Provider{DoQAddr: listener.Addr().String(), DoQName: "resolver.test"}, wire, &tls.Config{RootCAs: roots}, &quic.Config{}); err == nil {
		t.Fatal("DoQ timeout was accepted")
	}
}

func TestExchangeDoQRejectsALPNMismatch(t *testing.T) {
	listener, roots := newDoQTestListener(t, "not-doq")
	defer listener.Close()
	wire, _, _, _ := BuildQuery("example.com", "A")
	binary.BigEndian.PutUint16(wire[:2], 0)
	_, _, err := exchangeDoQWithConfig(t.Context(), Provider{DoQAddr: listener.Addr().String(), DoQName: "resolver.test"}, wire, &tls.Config{RootCAs: roots}, &quic.Config{})
	if err == nil {
		t.Fatal("DoQ ALPN mismatch was accepted")
	}
}

func newDoQTestListener(t *testing.T, alpn string) (*quic.Listener, *x509.CertPool) {
	t.Helper()
	certificate, roots := newTestCertificate(t, "resolver.test")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("listen for DoQ: %v", err)
	}
	return listener, roots
}
