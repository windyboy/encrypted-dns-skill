package edns

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestResolveProxyUsesExplicitURLBeforeEnvironment(t *testing.T) {
	original := proxyFromEnvironment
	t.Cleanup(func() { proxyFromEnvironment = original })
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) {
		t.Fatal("environment proxy selector was called for an explicit proxy")
		return nil, nil
	}

	proxyURL, err := resolveProxy(&url.URL{Scheme: "https", Host: "resolver.example"}, "http://user:secret@proxy.example:8080")
	if err != nil {
		t.Fatalf("resolve explicit proxy: %v", err)
	}
	if got := proxyDisplayURL(proxyURL); got != "http://proxy.example:8080" {
		t.Fatalf("display URL = %q, want credentials removed", got)
	}
}

func TestResolveProxyUsesStandardEnvironmentSelector(t *testing.T) {
	original := proxyFromEnvironment
	t.Cleanup(func() { proxyFromEnvironment = original })
	want, _ := url.Parse("HTTPS://proxy.example:3128")
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		if request.URL.Scheme != "https" || request.URL.Host != "resolver.example:853" {
			t.Fatalf("environment selector request URL = %s", request.URL)
		}
		return want, nil
	}

	got, err := resolveProxy(&url.URL{Scheme: "https", Host: "resolver.example:853"}, "")
	if err != nil {
		t.Fatalf("resolve environment proxy: %v", err)
	}
	if got.String() != "https://proxy.example:3128" {
		t.Fatalf("proxy = %v, want normalized HTTPS URL", got)
	}
}

func TestValidateProxyURL(t *testing.T) {
	for _, valid := range []string{"", "http://proxy.example:8080", "https://user:pass@proxy.example", "HTTPS://proxy.example"} {
		if err := ValidateProxyURL(valid); err != nil {
			t.Fatalf("ValidateProxyURL(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{"proxy.example:8080", "socks5://proxy.example:1080", "http://proxy.example/path"} {
		if err := ValidateProxyURL(invalid); err == nil {
			t.Fatalf("ValidateProxyURL(%q) succeeded, want error", invalid)
		}
	}
}

func TestReadCONNECTResponseBoundsHeaders(t *testing.T) {
	request := &http.Request{Method: http.MethodConnect}
	oversized := "HTTP/1.1 200 Connection Established\r\nX-Test: " + strings.Repeat("a", maxProxyResponseHeaderSize)
	if _, err := readCONNECTResponse(strings.NewReader(oversized), request); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("oversized CONNECT response error = %v", err)
	}
}

func startConnectProxy(t *testing.T, expectedTarget, expectedAuthorization string) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for CONNECT proxy: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	result := make(chan error, 1)
	go func() {
		client, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer client.Close()
		reader := bufio.NewReader(client)
		request, err := http.ReadRequest(reader)
		if err != nil {
			result <- err
			return
		}
		if request.Method != http.MethodConnect || request.Host != expectedTarget {
			result <- fmt.Errorf("CONNECT request = %s %s, want target %s", request.Method, request.Host, expectedTarget)
			return
		}
		if got := request.Header.Get("Proxy-Authorization"); got != expectedAuthorization {
			result <- fmt.Errorf("Proxy-Authorization = %q, want %q", got, expectedAuthorization)
			return
		}
		upstream, err := net.Dial("tcp", expectedTarget)
		if err != nil {
			result <- err
			return
		}
		defer upstream.Close()
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			result <- err
			return
		}
		copies := make(chan error, 2)
		go func() {
			_, copyErr := io.Copy(upstream, reader)
			copies <- copyErr
		}()
		go func() {
			_, copyErr := io.Copy(client, upstream)
			copies <- copyErr
		}()
		err = <-copies
		client.Close()
		upstream.Close()
		<-copies
		result <- err
	}()
	return "http://user:secret@" + listener.Addr().String(), result
}
