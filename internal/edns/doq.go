package edns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	doqNoError       quic.ApplicationErrorCode = 0x0
	doqProtocolError quic.ApplicationErrorCode = 0x2
)

func exchangeDoQ(ctx context.Context, provider Provider, wire []byte) ([]byte, TransportInfo, error) {
	return exchangeDoQWithConfig(ctx, provider, wire, &tls.Config{
		ServerName: provider.DoQName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"doq"},
	}, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
}

func exchangeDoQWithConfig(ctx context.Context, provider Provider, wire []byte, tlsConfig *tls.Config, quicConfig *quic.Config) ([]byte, TransportInfo, error) {
	started := time.Now()
	info := TransportInfo{
		Protocol:  "doq",
		Encrypted: true,
		Bootstrap: "system_resolver",
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.ServerName = provider.DoQName
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{"doq"}
	connection, err := quic.DialAddr(ctx, provider.DoQAddr, tlsConfig, quicConfig)
	if err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, fmt.Errorf("authenticate DoQ server: %w", err)
	}
	defer connection.CloseWithError(doqNoError, "")

	state := connection.ConnectionState()
	info.TLSVersion = tlsVersionName(state.TLS.Version)
	info.ALPN = state.TLS.NegotiatedProtocol
	info.QUICVersion = state.Version.String()
	if len(state.TLS.VerifiedChains) == 0 {
		return nil, info, fmt.Errorf("DoQ server TLS identity was not verified")
	}
	if info.ALPN != "doq" {
		connection.CloseWithError(doqProtocolError, "unexpected ALPN")
		return nil, info, fmt.Errorf("DoQ server negotiated unexpected ALPN protocol %q", info.ALPN)
	}
	info.ServerAuthenticated = true

	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, fmt.Errorf("open DoQ query stream: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return nil, info, fmt.Errorf("set DoQ stream deadline: %w", err)
		}
	}
	if err := writeDNSFrame(stream, wire); err != nil {
		return nil, info, fmt.Errorf("write DoQ query: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, info, fmt.Errorf("finish DoQ query stream: %w", err)
	}

	response, err := readDNSFrame(stream)
	info.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		return nil, info, fmt.Errorf("read DoQ response: %w", err)
	}
	trailing, err := io.ReadAll(io.LimitReader(stream, 1))
	if err != nil {
		return nil, info, fmt.Errorf("finish DoQ response stream: %w", err)
	}
	if len(trailing) != 0 {
		return nil, info, fmt.Errorf("DoQ server returned more than one DNS response")
	}
	return response, info, nil
}

func writeDNSFrame(writer io.Writer, wire []byte) error {
	if len(wire) == 0 || len(wire) > maxDNSMessageSize {
		return fmt.Errorf("invalid DNS message length %d", len(wire))
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	return writeAll(writer, frame)
}

func readDNSFrame(reader io.Reader) ([]byte, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, fmt.Errorf("read DNS response length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length == 0 {
		return nil, fmt.Errorf("server returned an empty DNS message")
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(reader, response); err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}
	return response, nil
}
