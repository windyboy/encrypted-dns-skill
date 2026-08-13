package edns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

func exchangeDoT(ctx context.Context, provider Provider, wire []byte) ([]byte, TransportInfo, error) {
	return exchangeDoTWithTLSConfig(ctx, provider, wire, &tls.Config{
		ServerName: provider.DoTName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
	})
}

func exchangeDoTWithTLSConfig(ctx context.Context, provider Provider, wire []byte, tlsConfig *tls.Config) ([]byte, TransportInfo, error) {
	started := time.Now()
	info := TransportInfo{
		Protocol:  "dot",
		Encrypted: true,
		Bootstrap: "system_resolver",
	}

	rawConnection, err := (&net.Dialer{}).DialContext(ctx, "tcp", provider.DoTAddr)
	if err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, fmt.Errorf("connect to DoT server: %w", err)
	}
	defer rawConnection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConnection.SetDeadline(deadline); err != nil {
			return nil, info, fmt.Errorf("set DoT deadline: %w", err)
		}
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.ServerName = provider.DoTName
	tlsConnection := tls.Client(rawConnection, tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, fmt.Errorf("authenticate DoT server: %w", err)
	}
	state := tlsConnection.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		return nil, info, fmt.Errorf("DoT server TLS identity was not verified")
	}
	info.ServerAuthenticated = true
	info.TLSVersion = tlsVersionName(state.Version)
	info.ALPN = state.NegotiatedProtocol
	if info.ALPN != "" && info.ALPN != "dot" {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, fmt.Errorf("DoT server negotiated unexpected ALPN protocol %q", info.ALPN)
	}

	response, err := exchangeTCPFrame(tlsConnection, wire)
	info.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		return nil, info, fmt.Errorf("perform DoT exchange: %w", err)
	}
	return response, info, nil
}

func exchangeTCPFrame(connection io.ReadWriter, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > maxDNSMessageSize {
		return nil, fmt.Errorf("invalid DNS message length %d", len(wire))
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if err := writeAll(connection, frame); err != nil {
		return nil, fmt.Errorf("write framed DNS query: %w", err)
	}

	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		return nil, fmt.Errorf("read DNS response length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length == 0 {
		return nil, fmt.Errorf("DoT server returned an empty DNS message")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}
	return response, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
