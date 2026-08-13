package edns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxDNSMessageSize = 65535

func exchangeDoH(ctx context.Context, provider Provider, wire []byte, method string) ([]byte, TransportInfo, error) {
	client := newDoHClient(provider.DoHURL)
	return exchangeDoHWithClient(ctx, client, provider.DoHURL, wire, method)
}

func newDoHClient(endpoint string) *http.Client {
	origin, _ := url.Parse(endpoint)
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext:       (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many DoH redirects")
			}
			if request.URL.Scheme != "https" {
				return fmt.Errorf("DoH redirect changed to a non-HTTPS scheme")
			}
			if !strings.EqualFold(request.URL.Hostname(), origin.Hostname()) {
				return fmt.Errorf("DoH redirect changed authentication domain")
			}
			return nil
		},
	}
}

func exchangeDoHWithClient(ctx context.Context, client *http.Client, endpoint string, wire []byte, method string) ([]byte, TransportInfo, error) {
	return exchangeHTTPSDNSWithClient(ctx, client, endpoint, wire, method, "doh")
}

func exchangeHTTPSDNSWithClient(ctx context.Context, client *http.Client, endpoint string, wire []byte, method, protocol string) ([]byte, TransportInfo, error) {
	started := time.Now()
	info := TransportInfo{
		Protocol:  protocol,
		Encrypted: true,
		Bootstrap: "system_resolver",
	}

	requestURL := endpoint
	var body io.Reader
	switch strings.ToLower(method) {
	case "get":
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, info, fmt.Errorf("parse DoH endpoint: %w", err)
		}
		query := parsed.Query()
		query.Set("dns", base64.RawURLEncoding.EncodeToString(wire))
		parsed.RawQuery = query.Encode()
		requestURL = parsed.String()
	case "post", "":
		method = "post"
		body = bytes.NewReader(wire)
	default:
		return nil, info, fmt.Errorf("unsupported DoH method %q", method)
	}

	request, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), requestURL, body)
	if err != nil {
		return nil, info, fmt.Errorf("create DoH request: %w", err)
	}
	request.Header.Set("Accept", "application/dns-message")
	if strings.EqualFold(method, "post") {
		request.Header.Set("Content-Type", "application/dns-message")
	}
	request.Header.Set("User-Agent", "ednsdiag/0.1.0-dev")

	response, err := client.Do(request)
	info.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		return nil, info, fmt.Errorf("perform DoH exchange: %w", err)
	}
	defer response.Body.Close()

	info.HTTPVersion = response.Proto
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return nil, info, fmt.Errorf("DoH server TLS identity was not verified")
	}
	info.ServerAuthenticated = true
	info.TLSVersion = tlsVersionName(response.TLS.Version)
	info.ALPN = response.TLS.NegotiatedProtocol
	if protocol == "doh3" {
		if response.ProtoMajor != 3 {
			return nil, info, fmt.Errorf("DoH3 server used unexpected HTTP version %q", response.Proto)
		}
		if info.ALPN != "h3" {
			return nil, info, fmt.Errorf("DoH3 server negotiated unexpected ALPN protocol %q", info.ALPN)
		}
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, info, fmt.Errorf("DoH server returned HTTP status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/dns-message") {
		return nil, info, fmt.Errorf("DoH server returned unsupported content type %q", response.Header.Get("Content-Type"))
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, info, fmt.Errorf("read DoH response: %w", err)
	}
	if len(payload) > maxDNSMessageSize {
		return nil, info, fmt.Errorf("DoH response exceeds %d bytes", maxDNSMessageSize)
	}
	return payload, info, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
