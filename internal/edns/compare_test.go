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

func TestComparePassesProxyToEveryTarget(t *testing.T) {
	const proxyURL = "http://proxy.example:8080"
	result := compareWithQuery(t.Context(), CompareOptions{
		Name: "example.com", RecordType: "A", AttemptTimeout: time.Second, MaxAttempts: 2, Proxy: proxyURL,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare", Method: "post"},
			{Protocol: "dot", Provider: "google", Method: "post"},
		},
	}, func(_ context.Context, query QueryOptions) Result {
		if query.Proxy != proxyURL {
			return failedCompareResult(query, "internal", "proxy was not propagated")
		}
		return completedCompareAttempt(query)
	})
	if !result.Completed {
		t.Fatalf("unexpected comparison result: %#v", result)
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

func TestCompareStartsTargetsIndependentlyAndPreservesOrder(t *testing.T) {
	targets := []CompareTarget{
		{Protocol: "doh", Provider: "cloudflare", Method: "post"},
		{Protocol: "dot", Provider: "google", Method: "post"},
		{Protocol: "doh", Provider: "quad9", Method: "post"},
	}
	started := make(chan string, len(targets))
	release := make(chan struct{})
	resultChannel := make(chan CompareResult, 1)
	go func() {
		resultChannel <- compareWithQuery(t.Context(), CompareOptions{
			Name: "example.com", RecordType: "A", AttemptTimeout: time.Second, MaxAttempts: 3, Targets: targets,
		}, func(ctx context.Context, query QueryOptions) Result {
			started <- query.Provider
			select {
			case <-release:
				return completedCompareAttempt(query)
			case <-ctx.Done():
				return failedCompareResult(query, "transport", ctx.Err().Error())
			}
		})
	}()

	seen := map[string]bool{}
	for range targets {
		select {
		case provider := <-started:
			seen[provider] = true
		case <-time.After(250 * time.Millisecond):
			t.Fatal("comparison serialized targets instead of starting them independently")
		}
	}
	close(release)
	result := <-resultChannel
	if len(seen) != len(targets) || !result.Completed {
		t.Fatalf("unexpected concurrent result: seen=%v result=%#v", seen, result)
	}
	for index, target := range targets {
		if result.Attempts[index].Resolver.Provider != target.Provider {
			t.Fatalf("attempt %d provider = %q, want %q", index, result.Attempts[index].Resolver.Provider, target.Provider)
		}
	}
}

func TestCompareMixedFailurePrefersTransport(t *testing.T) {
	result := compareWithQuery(t.Context(), CompareOptions{
		Name: "example.com", RecordType: "A", AttemptTimeout: time.Second, MaxAttempts: 2,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare", Method: "post"},
			{Protocol: "dot", Provider: "google", Method: "post"},
		},
	}, func(_ context.Context, query QueryOptions) Result {
		if query.Provider == "cloudflare" {
			return failedCompareResult(query, "unsupported", "unsupported fixture")
		}
		return failedCompareResult(query, "transport", "transport fixture")
	})
	if result.Error == nil || result.Error.Class != "transport" || result.Summary.Unsupported != 1 {
		t.Fatalf("unexpected mixed failure result: %#v", result)
	}
}

func TestCompareRejectsCanceledParentBeforeStartingTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	result := compareWithQuery(ctx, CompareOptions{
		Name: "example.com", RecordType: "A", AttemptTimeout: time.Second, MaxAttempts: 2,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare", Method: "post"},
			{Protocol: "dot", Provider: "google", Method: "post"},
		},
	}, func(_ context.Context, query QueryOptions) Result {
		calls++
		return completedCompareAttempt(query)
	})
	if calls != 0 || len(result.Attempts) != 0 || result.Error == nil || result.Error.Class != "transport" {
		t.Fatalf("unexpected canceled comparison: calls=%d result=%#v", calls, result)
	}
}

func completedCompareAttempt(query QueryOptions) Result {
	return Result{
		SchemaVersion: 1, Operation: "query", Completed: true,
		Query:     QueryInfo{Name: "example.com", Type: "A"},
		Resolver:  ResolverInfo{Provider: query.Provider, Endpoint: "fixture.example:443", Profile: "test"},
		Transport: testTransport(query.Protocol, 0),
		DNS: DNSInfo{RCode: "NOERROR", Answers: []AnswerRecord{{
			"name": "example.com", "type": "A", "ttl": uint32(60), "address": "192.0.2.1",
		}}},
	}
}

func failedCompareResult(query QueryOptions, class, message string) Result {
	result := completedCompareAttempt(query)
	result.Completed = false
	result.Error = &ErrorInfo{Class: class, Message: message}
	return result
}
