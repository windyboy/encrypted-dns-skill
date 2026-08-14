package edns

import (
	"context"
	"fmt"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestQueryUsesZeroMessageIDForHTTPAndQUIC(t *testing.T) {
	tests := []struct {
		protocol string
		provider string
	}{
		{protocol: "doh", provider: "cloudflare"},
		{protocol: "doh3", provider: "cloudflare"},
		{protocol: "doq", provider: "adguard"},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			result := queryWithExchange(t.Context(), QueryOptions{
				Name: "example.com", RecordType: "A", Protocol: test.protocol, Provider: test.provider, Method: "post",
			}, successfulTestExchange(0, 0))
			if !result.Completed || result.Error != nil {
				t.Fatalf("unexpected result: %#v", result)
			}
		})
	}
}

func TestQueryReturnsProtocolErrorForTruncatedResponse(t *testing.T) {
	exchange := func(_ context.Context, _ Provider, wire []byte, options QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
		var request dnsmessage.Message
		if err := request.Unpack(wire); err != nil {
			return nil, TransportInfo{}, dnsCryptPeerInfo{}, err
		}
		message := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: request.Header.ID, Response: true, Truncated: true},
			Questions: request.Questions,
		}
		response, err := message.Pack()
		return response, testTransport(options.Protocol, 0), dnsCryptPeerInfo{}, err
	}
	result := queryWithExchange(t.Context(), QueryOptions{
		Name: "example.com", RecordType: "A", Protocol: "doh", Provider: "cloudflare", Method: "post",
	}, exchange)
	if result.Completed || result.Error == nil || result.Error.Class != "protocol" {
		t.Fatalf("truncated response was not a protocol failure: %#v", result)
	}
}

func TestQueryRejectsExplicitProxyForUDPProtocol(t *testing.T) {
	called := false
	result := queryWithExchange(t.Context(), QueryOptions{
		Name: "example.com", RecordType: "A", Protocol: "doq", Provider: "adguard", Method: "post", Proxy: "http://proxy.example:8080",
	}, func(context.Context, Provider, []byte, QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
		called = true
		return nil, TransportInfo{}, dnsCryptPeerInfo{}, nil
	})
	if called || result.Completed || result.Error == nil || result.Error.Class != "unsupported" {
		t.Fatalf("unexpected proxy result: called=%v result=%#v", called, result)
	}
}

func TestQueryTreatsREFUSEDAndNODATAAsCompletedDNSOutcomes(t *testing.T) {
	tests := []struct {
		name  string
		rcode dnsmessage.RCode
		want  string
	}{
		{name: "REFUSED", rcode: dnsmessage.RCodeRefused, want: "REFUSED"},
		{name: "NODATA", rcode: dnsmessage.RCodeSuccess, want: "NOERROR"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exchange := func(_ context.Context, _ Provider, wire []byte, options QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
				var request dnsmessage.Message
				if err := request.Unpack(wire); err != nil {
					return nil, TransportInfo{}, dnsCryptPeerInfo{}, err
				}
				message := dnsmessage.Message{
					Header:    dnsmessage.Header{ID: request.Header.ID, Response: true, RCode: test.rcode},
					Questions: request.Questions,
				}
				response, err := message.Pack()
				return response, testTransport(options.Protocol, 0), dnsCryptPeerInfo{}, err
			}
			result := queryWithExchange(t.Context(), QueryOptions{
				Name: "example.com", RecordType: "A", Protocol: "doh", Provider: "cloudflare", Method: "post",
			}, exchange)
			if !result.Completed || result.Error != nil || result.DNS.RCode != test.want || len(result.DNS.Answers) != 0 {
				t.Fatalf("unexpected %s result: %#v", test.name, result)
			}
		})
	}
}

func TestQueryAppliesHTTPAgeToAnswerTTL(t *testing.T) {
	result := queryWithExchange(t.Context(), QueryOptions{
		Name: "example.com", RecordType: "A", Protocol: "doh", Provider: "cloudflare", Method: "post",
	}, successfulTestExchange(0, 45))
	if !result.Completed || result.Error != nil {
		t.Fatalf("unexpected result: %#v", result)
	}
	if got := result.DNS.Answers[0]["ttl"]; got != uint32(75) {
		t.Fatalf("aged TTL = %#v, want 75", got)
	}
	if result.Transport.HTTPAgeSeconds != 45 {
		t.Fatalf("HTTP age = %d, want 45", result.Transport.HTTPAgeSeconds)
	}
}

func successfulTestExchange(expectedID uint16, ageSeconds int64) queryExchange {
	return func(_ context.Context, _ Provider, wire []byte, options QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
		var request dnsmessage.Message
		if err := request.Unpack(wire); err != nil {
			return nil, TransportInfo{}, dnsCryptPeerInfo{}, err
		}
		if request.Header.ID != expectedID {
			return nil, TransportInfo{}, dnsCryptPeerInfo{}, fmt.Errorf("query ID = %d, want %d", request.Header.ID, expectedID)
		}
		message := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: request.Header.ID, Response: true, RecursionAvailable: true},
			Questions: request.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
			}},
		}
		response, err := message.Pack()
		return response, testTransport(options.Protocol, ageSeconds), dnsCryptPeerInfo{}, err
	}
}

func testTransport(protocol string, ageSeconds int64) TransportInfo {
	return TransportInfo{
		Protocol: protocol, Encrypted: true, ServerAuthenticated: true,
		ElapsedMS: 1, Bootstrap: "test_fixture", HTTPAgeSeconds: ageSeconds,
	}
}
