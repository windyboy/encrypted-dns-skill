package edns

import (
	"context"
	"testing"
	"time"
)

func TestCompareKeepsTargetResultsSeparate(t *testing.T) {
	options := CompareOptions{
		Name:           "example.com",
		RecordType:     "A",
		AttemptTimeout: time.Second,
		MaxAttempts:    4,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare", Method: "post"},
			{Protocol: "dot", Provider: "google", Method: "post"},
		},
	}
	result := compareWithQuery(t.Context(), options, func(_ context.Context, query QueryOptions) Result {
		return Result{
			SchemaVersion: 1,
			Operation:     "query",
			Completed:     true,
			Query:         QueryInfo{Name: "example.com", Type: "A"},
			Resolver:      ResolverInfo{Provider: query.Provider},
			Transport:     TransportInfo{Protocol: query.Protocol, Encrypted: true, ServerAuthenticated: true},
			DNS: DNSInfo{RCode: "NOERROR", Answers: []AnswerRecord{{
				"name": "example.com", "type": "A", "ttl": uint32(60), "address": query.Provider,
			}}},
		}
	})
	if !result.Completed || result.Summary.Completed != 2 || len(result.Attempts) != 2 {
		t.Fatalf("unexpected compare result: %#v", result)
	}
	if result.Attempts[0].Resolver.Provider != "cloudflare" || result.Attempts[1].Resolver.Provider != "google" {
		t.Fatalf("comparison targets were merged or reordered: %#v", result.Attempts)
	}
	if result.Attempts[0].DNS.Answers[0]["address"] == result.Attempts[1].DNS.Answers[0]["address"] {
		t.Fatal("comparison answers were merged")
	}
}

func TestCompareReportsUnsupportedAttempts(t *testing.T) {
	result := Compare(t.Context(), CompareOptions{
		Name:           "example.com",
		RecordType:     "A",
		AttemptTimeout: time.Second,
		MaxAttempts:    2,
		Targets: []CompareTarget{
			{Protocol: "doq", Provider: "cloudflare", Method: "post"},
			{Protocol: "dnscrypt", Provider: "cloudflare", Method: "post"},
		},
	})
	if result.Completed || result.Error == nil || result.Error.Class != "unsupported" {
		t.Fatalf("unexpected unsupported comparison result: %#v", result)
	}
	if result.Summary.Unsupported != 2 || len(result.Attempts) != 2 {
		t.Fatalf("unsupported attempts not preserved: %#v", result)
	}
}

func TestCompareValidatesAttemptLimits(t *testing.T) {
	result := Compare(t.Context(), CompareOptions{
		Name:           "example.com",
		RecordType:     "A",
		AttemptTimeout: time.Second,
		MaxAttempts:    2,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare"},
			{Protocol: "dot", Provider: "google"},
			{Protocol: "doh", Provider: "quad9"},
		},
	})
	if result.Error == nil || result.Error.Class != "input" || len(result.Attempts) != 0 {
		t.Fatalf("attempt limit was not enforced before execution: %#v", result)
	}
}
