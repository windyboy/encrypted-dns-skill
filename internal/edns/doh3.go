package edns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type quicStateCapture struct {
	state quic.ConnectionState
	set   bool
}

func exchangeDoH3(ctx context.Context, provider Provider, wire []byte, method string) ([]byte, TransportInfo, error) {
	return exchangeDoH3WithTLSConfig(ctx, provider.DoH3URL, wire, method, nil)
}

func exchangeDoH3WithTLSConfig(ctx context.Context, endpoint string, wire []byte, method string, tlsConfig *tls.Config) ([]byte, TransportInfo, error) {
	client, transport, capture, err := newDoH3Client(endpoint, tlsConfig)
	if err != nil {
		return nil, TransportInfo{Protocol: "doh3", Encrypted: true, Bootstrap: "system_resolver"}, err
	}
	defer transport.Close()

	response, info, err := exchangeHTTPSDNSWithClient(ctx, client, endpoint, wire, method, "doh3")
	if capture.set {
		info.QUICVersion = capture.state.Version.String()
	}
	return response, info, err
}

func newDoH3Client(endpoint string, tlsConfig *tls.Config) (*http.Client, *http3.Transport, *quicStateCapture, error) {
	origin, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse DoH3 endpoint: %w", err)
	}
	if origin.Scheme != "https" || origin.Hostname() == "" {
		return nil, nil, nil, fmt.Errorf("DoH3 endpoint must use HTTPS with an authentication domain")
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.ServerName = origin.Hostname()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.NextProtos = []string{http3.NextProtoH3}

	capture := &quicStateCapture{}
	transport := &http3.Transport{
		TLSClientConfig:        tlsConfig,
		QUICConfig:             &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second},
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
		Dial: func(ctx context.Context, address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Conn, error) {
			connection, err := quic.DialAddr(ctx, address, tlsConfig, config)
			if err == nil {
				capture.state = connection.ConnectionState()
				capture.set = true
			}
			return connection, err
		},
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many DoH3 redirects")
			}
			if request.URL.Scheme != "https" {
				return fmt.Errorf("DoH3 redirect changed to a non-HTTPS scheme")
			}
			if !strings.EqualFold(request.URL.Hostname(), origin.Hostname()) {
				return fmt.Errorf("DoH3 redirect changed authentication domain")
			}
			return nil
		},
	}
	return client, transport, capture, nil
}
