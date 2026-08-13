package edns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestExchangeDoH3(t *testing.T) {
	server, endpoint, roots := newDoH3TestServer(t, func(writer http.ResponseWriter, request *http.Request) {
		var wire []byte
		var err error
		if request.Method == http.MethodGet {
			wire, err = decodeGETQuery(request.URL.Query().Get("dns"))
		} else {
			wire, err = io.ReadAll(request.Body)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(wire); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		responseMessage := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RCode: dnsmessage.RCodeServerFailure},
			Questions: query.Questions,
		}
		response, err := responseMessage.Pack()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	})
	defer server.Close()

	wire, query, transactionID, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	for _, method := range []string{"get", "post"} {
		t.Run(method, func(t *testing.T) {
			response, info, err := exchangeDoH3WithTLSConfig(t.Context(), endpoint, wire, method, &tls.Config{RootCAs: roots})
			if err != nil {
				t.Fatalf("exchange DoH3: %v", err)
			}
			if !info.ServerAuthenticated || info.ALPN != "h3" || info.HTTPVersion != "HTTP/3.0" || info.QUICVersion == "" || info.TLSVersion != "TLS1.3" {
				t.Fatalf("unexpected transport info: %#v", info)
			}
			dnsResult, err := ParseResponse(response, transactionID, query)
			if err != nil {
				t.Fatalf("parse DoH3 response: %v", err)
			}
			if dnsResult.RCode != "SERVFAIL" {
				t.Fatalf("rcode = %q, want SERVFAIL", dnsResult.RCode)
			}
		})
	}
}

func TestExchangeDoH3RejectsMalformedDNSMessage(t *testing.T) {
	server, endpoint, roots := newDoH3TestServer(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write([]byte{1, 2, 3})
	})
	defer server.Close()

	wire, query, transactionID, _ := BuildQuery("example.com", "A")
	response, _, err := exchangeDoH3WithTLSConfig(t.Context(), endpoint, wire, "post", &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatalf("HTTP/3 exchange failed before DNS validation: %v", err)
	}
	if _, err := ParseResponse(response, transactionID, query); err == nil {
		t.Fatal("malformed DoH3 DNS response was accepted")
	}
}

func TestExchangeDoH3TimesOut(t *testing.T) {
	server, endpoint, roots := newDoH3TestServer(t, func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	})
	defer server.Close()

	wire, _, _, _ := BuildQuery("example.com", "A")
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := exchangeDoH3WithTLSConfig(ctx, endpoint, wire, "post", &tls.Config{RootCAs: roots}); err == nil {
		t.Fatal("DoH3 timeout was accepted")
	}
}

func TestExchangeDoH3RejectsUnexpectedALPN(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Proto:      "HTTP/3.0",
			ProtoMajor: 3,
			Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
			Body:       io.NopCloser(strings.NewReader("response")),
			TLS: &tls.ConnectionState{
				Version:            tls.VersionTLS13,
				NegotiatedProtocol: "unexpected",
				VerifiedChains:     [][]*x509.Certificate{{new(x509.Certificate)}},
			},
		}, nil
	})}
	_, _, err := exchangeHTTPSDNSWithClient(t.Context(), client, "https://resolver.test/dns-query", []byte{1}, "post", "doh3")
	if err == nil || !strings.Contains(err.Error(), "unexpected ALPN") {
		t.Fatalf("error = %v, want ALPN mismatch", err)
	}
}

func newDoH3TestServer(t *testing.T, handler http.HandlerFunc) (*http3.Server, string, *x509.CertPool) {
	t.Helper()
	certificate, roots := newTestCertificate(t, "127.0.0.1")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{http3.NextProtoH3},
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("listen for HTTP/3: %v", err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: tlsConfig}
	go func() {
		_ = server.ServeListener(listener)
	}()
	return server, "https://" + listener.Addr().String() + "/dns-query", roots
}
