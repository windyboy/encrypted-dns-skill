package edns

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type scriptedReadWriter struct {
	read    *bytes.Reader
	written bytes.Buffer
}

func (stream *scriptedReadWriter) Read(payload []byte) (int, error) {
	return stream.read.Read(payload)
}

func (stream *scriptedReadWriter) Write(payload []byte) (int, error) {
	return stream.written.Write(payload)
}

func TestExchangeTCPFrame(t *testing.T) {
	responsePayload := []byte{9, 8, 7}
	framedResponse := make([]byte, 2+len(responsePayload))
	binary.BigEndian.PutUint16(framedResponse[:2], uint16(len(responsePayload)))
	copy(framedResponse[2:], responsePayload)
	stream := &scriptedReadWriter{read: bytes.NewReader(framedResponse)}

	query := []byte{1, 2, 3, 4}
	response, err := exchangeTCPFrame(stream, query)
	if err != nil {
		t.Fatalf("exchange TCP frame: %v", err)
	}
	if !bytes.Equal(response, responsePayload) {
		t.Fatalf("response = %v, want %v", response, responsePayload)
	}
	written := stream.written.Bytes()
	if int(binary.BigEndian.Uint16(written[:2])) != len(query) || !bytes.Equal(written[2:], query) {
		t.Fatalf("invalid query frame: %v", written)
	}
}

func TestExchangeDoTAuthenticatesServer(t *testing.T) {
	certificate, roots := newTestCertificate(t, "resolver.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"dot"},
	})
	if err != nil {
		t.Fatalf("listen for DoT: %v", err)
	}
	defer listener.Close()

	serverError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}
		defer connection.Close()
		response, err := serveOneDoTQuery(connection)
		if err == nil {
			err = writeAll(connection, response)
		}
		serverError <- err
	}()

	queryWire, query, transactionID, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, info, err := exchangeDoTWithTLSConfig(ctx, Provider{DoTAddr: listener.Addr().String(), DoTName: "resolver.test"}, queryWire, &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
	})
	if err != nil {
		t.Fatalf("exchange DoT: %v", err)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("serve DoT: %v", err)
	}
	if !info.ServerAuthenticated || info.ALPN != "dot" {
		t.Fatalf("unexpected transport info: %#v", info)
	}
	if _, err := ParseResponse(response, transactionID, query); err != nil {
		t.Fatalf("parse response: %v", err)
	}
}

func TestExchangeDoTAllowsMissingALPN(t *testing.T) {
	certificate, roots := newTestCertificate(t, "resolver.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen for DoT: %v", err)
	}
	defer listener.Close()

	serverError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}
		defer connection.Close()
		response, err := serveOneDoTQuery(connection)
		if err == nil {
			err = writeAll(connection, response)
		}
		serverError <- err
	}()

	queryWire, _, _, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, info, err := exchangeDoTWithTLSConfig(ctx, Provider{DoTAddr: listener.Addr().String(), DoTName: "resolver.test"}, queryWire, &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
	})
	if err != nil {
		t.Fatalf("exchange DoT without ALPN: %v", err)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("serve DoT: %v", err)
	}
	if !info.ServerAuthenticated || info.ALPN != "" {
		t.Fatalf("unexpected transport info: %#v", info)
	}
	if _, err := ParseResponse(response, binary.BigEndian.Uint16(queryWire[:2]), QueryInfo{Name: "example.com", Type: "A"}); err != nil {
		t.Fatalf("parse response without ALPN: %v", err)
	}
}

func TestExchangeDoTRejectsUnexpectedALPN(t *testing.T) {
	certificate, roots := newTestCertificate(t, "resolver.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("listen for TLS: %v", err)
	}
	defer listener.Close()

	serverError := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}
		defer connection.Close()
		serverError <- connection.(*tls.Conn).Handshake()
	}()

	queryWire, _, _, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, info, err := exchangeDoTWithTLSConfig(ctx, Provider{DoTAddr: listener.Addr().String(), DoTName: "resolver.test"}, queryWire, &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected ALPN protocol") {
		t.Fatalf("exchange DoT error = %v, want unexpected ALPN error", err)
	}
	if err := <-serverError; err != nil {
		t.Fatalf("complete TLS handshake: %v", err)
	}
	if !info.ServerAuthenticated || info.ALPN != "http/1.1" {
		t.Fatalf("unexpected transport info: %#v", info)
	}
}

func newTestCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if address := net.ParseIP(name); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, roots
}

func serveOneDoTQuery(connection net.Conn) ([]byte, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return nil, err
	}
	wire := make([]byte, int(binary.BigEndian.Uint16(lengthBytes[:])))
	if _, err := io.ReadFull(connection, wire); err != nil {
		return nil, err
	}
	var query dnsmessage.Message
	if err := query.Unpack(wire); err != nil {
		return nil, err
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true},
		Questions: query.Questions,
	}
	responseWire, err := response.Pack()
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(responseWire))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(responseWire)))
	copy(framed[2:], responseWire)
	return framed, nil
}
