package edns

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var proxyFromEnvironment = http.ProxyFromEnvironment

const maxProxyResponseHeaderSize = 32 * 1024

// ValidateProxyURL validates an explicit HTTP CONNECT proxy URL. An empty
// value means that the standard proxy environment variables should be used.
func ValidateProxyURL(raw string) error {
	if raw == "" {
		return nil
	}
	_, err := parseProxyURL(raw)
	return err
}

func resolveProxy(endpoint *url.URL, explicit string) (*url.URL, error) {
	if explicit != "" {
		return parseProxyURL(explicit)
	}
	proxyURL, err := proxyFromEnvironment(&http.Request{URL: endpoint})
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return nil, nil
	}
	validated, err := parseProxyURL(proxyURL.String())
	if err != nil {
		return nil, err
	}
	return validated, nil
}

func parseProxyURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("proxy must be an absolute http:// or https:// URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("proxy scheme must be http or https")
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must not contain a path, query, or fragment")
	}
	return parsed, nil
}

func proxyDisplayURL(proxyURL *url.URL) string {
	if proxyURL == nil {
		return ""
	}
	copy := *proxyURL
	copy.User = nil
	copy.Path = ""
	copy.RawPath = ""
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func dialTCP(ctx context.Context, target string, proxyURL *url.URL) (net.Conn, error) {
	if proxyURL == nil {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	proxyAddress := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddress = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			connection.Close()
			return nil, fmt.Errorf("set proxy deadline: %w", err)
		}
	}
	if proxyURL.Scheme == "https" {
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			connection.Close()
			return nil, fmt.Errorf("authenticate HTTPS proxy: %w", err)
		}
		connection = tlsConnection
	}

	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := request.Write(connection); err != nil {
		connection.Close()
		return nil, fmt.Errorf("write proxy CONNECT request: %w", err)
	}
	response, err := readCONNECTResponse(connection, request)
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("read proxy CONNECT response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		connection.Close()
		return nil, fmt.Errorf("proxy CONNECT returned HTTP status %d", response.StatusCode)
	}
	return connection, nil
}

func readCONNECTResponse(reader io.Reader, request *http.Request) (*http.Response, error) {
	header := make([]byte, 0, 512)
	var next [1]byte
	for len(header) < maxProxyResponseHeaderSize {
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			return nil, err
		}
		header = append(header, next[0])
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), request)
		}
	}
	return nil, fmt.Errorf("proxy CONNECT response headers exceed %d bytes", maxProxyResponseHeaderSize)
}
