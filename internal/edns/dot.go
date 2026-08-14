package edns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"time"
)

func exchangeDoT(ctx context.Context, provider Provider, wire []byte, explicitProxy string) ([]byte, TransportInfo, error) {
	return exchangeDoTWithTLSConfigAndProxy(ctx, provider, wire, &tls.Config{
		ServerName: provider.DoTName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"dot"},
	}, explicitProxy)
}

func exchangeDoTWithTLSConfig(ctx context.Context, provider Provider, wire []byte, tlsConfig *tls.Config) ([]byte, TransportInfo, error) {
	return exchangeDoTWithTLSConfigAndProxy(ctx, provider, wire, tlsConfig, "")
}

func exchangeDoTWithTLSConfigAndProxy(ctx context.Context, provider Provider, wire []byte, tlsConfig *tls.Config, explicitProxy string) ([]byte, TransportInfo, error) {
	started := time.Now()
	info := TransportInfo{
		Protocol:  "dot",
		Encrypted: true,
		Bootstrap: "system_resolver",
	}

	endpoint := &url.URL{Scheme: "https", Host: provider.DoTAddr}
	proxyURL, err := resolveProxy(endpoint, explicitProxy)
	if err != nil {
		return nil, info, fmt.Errorf("select DoT proxy: %w", err)
	}
	info.Proxy = proxyDisplayURL(proxyURL)
	rawConnection, err := dialTCP(ctx, provider.DoTAddr, proxyURL)
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
	if err := writeDNSFrame(connection, wire); err != nil {
		return nil, fmt.Errorf("write framed DNS query: %w", err)
	}
	return readDNSFrame(connection)
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
