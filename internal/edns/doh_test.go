package edns

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestExchangeDoHGETAndPOST(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload []byte
		var err error
		if request.Method == http.MethodGet {
			payload, err = decodeGETQuery(request.URL.Query().Get("dns"))
		} else {
			payload, err = io.ReadAll(request.Body)
		}
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Header.Get("Accept") != "application/dns-message" {
			http.Error(writer, "missing accept", http.StatusNotAcceptable)
			return
		}

		var query dnsmessage.Message
		if err := query.Unpack(payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.Header.ID, Response: true, RecursionAvailable: true},
			Questions: query.Questions,
		}
		responseWire, err := response.Pack()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.Header().Set("Age", "10")
		_, _ = writer.Write(responseWire)
	}))
	defer server.Close()

	wire, _, _, err := BuildQuery("example.com", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	for _, method := range []string{"get", "post"} {
		t.Run(method, func(t *testing.T) {
			response, info, err := exchangeDoHWithClient(t.Context(), server.Client(), server.URL, wire, method)
			if err != nil {
				t.Fatalf("exchange DoH: %v", err)
			}
			if len(response) == 0 || !info.Encrypted || !info.ServerAuthenticated || info.HTTPAgeSeconds != 10 {
				t.Fatalf("unexpected result: response=%d info=%#v", len(response), info)
			}
		})
	}
}

func TestExchangeDoHRejectsInvalidAge(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.Header().Set("Age", "invalid")
		_, _ = writer.Write([]byte{1})
	}))
	defer server.Close()

	if _, _, err := exchangeDoHWithClient(t.Context(), server.Client(), server.URL, []byte{1}, "post"); err == nil {
		t.Fatal("invalid HTTP Age was accepted")
	}
}

func TestExchangeDoHRejectsHTTPError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if _, _, err := exchangeDoHWithClient(t.Context(), server.Client(), server.URL, []byte{1}, "post"); err == nil {
		t.Fatal("HTTP error was accepted")
	}
}
