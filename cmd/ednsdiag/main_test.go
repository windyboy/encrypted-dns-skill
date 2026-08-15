package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/windyboy/encrypted-dns-skill/internal/edns"
)

func TestCapabilities(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"capabilities"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run capabilities returned %d; stderr=%q", code, stderr.String())
	}

	var result capabilitiesResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if result.SchemaVersion != 1 || result.Command != "capabilities" {
		t.Fatalf("unexpected capabilities envelope: %#v", result)
	}
	available := map[string]bool{}
	for _, item := range result.Capabilities {
		available[item.Protocol] = item.Status == "available"
	}
	if !available["doh"] || !available["dot"] || !available["doq"] || !available["doh3"] || !available["dnscrypt"] {
		t.Fatalf("DoH, DoT, DoQ, DoH3, and DNSCrypt must be available: %#v", available)
	}
}

func TestQueryProbeAndCompareGoldenContracts(t *testing.T) {
	originalQuery, originalProbe, originalCompare := runQuery, runProbe, runCompare
	t.Cleanup(func() {
		runQuery, runProbe, runCompare = originalQuery, originalProbe, originalCompare
	})

	queryCalls := 0
	probeCalls := 0
	runQuery = func(_ context.Context, options edns.QueryOptions) edns.Result {
		queryCalls++
		return successfulResult("query", options.Protocol, options.Provider, "203.0.113.10")
	}
	runProbe = func(_ context.Context, options edns.QueryOptions) edns.Result {
		probeCalls++
		return successfulResult("probe", options.Protocol, options.Provider, "203.0.113.10")
	}
	runCompare = func(_ context.Context, _ edns.CompareOptions) edns.CompareResult {
		first := successfulResult("query", "doh", "cloudflare", "203.0.113.10")
		second := successfulResult("query", "dot", "google", "203.0.113.20")
		return edns.CompareResult{
			SchemaVersion: 1,
			Operation:     "compare",
			Completed:     true,
			Query:         edns.QueryInfo{Name: "example.com", Type: "A"},
			Attempts:      []edns.Result{first, second},
			Summary:       edns.CompareSummary{Total: 2, Completed: 2},
		}
	}

	tests := []struct {
		name   string
		args   []string
		golden string
	}{
		{name: "query", args: []string{"query", "example.com", "A"}, golden: "query.golden.json"},
		{name: "probe", args: []string{"probe", "example.com", "A"}, golden: "probe.golden.json"},
		{name: "compare", args: []string{"compare", "example.com", "A", "--target", "doh:cloudflare", "--target", "dot:google"}, golden: "compare.golden.json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			if code := run(test.args, &stdout, &stderr); code != exitSuccess {
				t.Fatalf("run returned %d; stderr=%q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			want, err := os.ReadFile(filepath.Join("testdata", test.golden))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if !bytes.Equal(stdout.Bytes(), want) {
				t.Fatalf("stdout does not match %s\nwant:\n%s\ngot:\n%s", test.golden, want, stdout.Bytes())
			}
			validateResultSchema(t, stdout.Bytes())
		})
	}

	if queryCalls != 1 || probeCalls != 1 {
		t.Fatalf("query calls = %d, probe calls = %d; each operation must invoke only its own runner", queryCalls, probeCalls)
	}
}

func TestUnsupportedProtocolReturnsStableJSONAndExitCode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"query", "example.com", "A", "--protocol", "odoh", "--provider", "cloudflare"}, &stdout, &stderr)
	if code != exitUnsupported {
		t.Fatalf("run returned %d, want %d; stderr=%q", code, exitUnsupported, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty for a structured operational result", stderr.String())
	}
	var result edns.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Error == nil || result.Error.Class != "unsupported" {
		t.Fatalf("unexpected error result: %#v", result)
	}
	validateResultSchema(t, stdout.Bytes())
}

func TestUsageDiagnosticsStayOnStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"compare", "example.com", "--target", "doh:cloudflare"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("run returned %d, want %d", code, exitUsage)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "at least two") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestParseQueryArgsAllowsSupportedAndResearchProtocols(t *testing.T) {
	for _, protocol := range []string{"dot", "doq", "doh3", "dnscrypt", "odoh", "anonymized-dnscrypt"} {
		t.Run(protocol, func(t *testing.T) {
			options, timeout, err := parseQueryArgs([]string{"example.com", "MX", "--protocol", protocol, "--provider=quad9", "--timeout", "3s"})
			if err != nil {
				t.Fatalf("parse query args: %v", err)
			}
			if options.Protocol != protocol || timeout != 3*time.Second {
				t.Fatalf("unexpected options=%#v timeout=%v", options, timeout)
			}
		})
	}
}

func TestParseQueryArgsAcceptsProxyForDoHAndDoTOnly(t *testing.T) {
	for _, protocol := range []string{"doh", "dot"} {
		options, _, err := parseQueryArgs([]string{"example.com", "--protocol", protocol, "--proxy", "http://proxy.example:8080"})
		if err != nil {
			t.Fatalf("parse %s proxy: %v", protocol, err)
		}
		if options.Proxy != "http://proxy.example:8080" {
			t.Fatalf("proxy = %q", options.Proxy)
		}
	}
	if _, _, err := parseQueryArgs([]string{"example.com", "--protocol", "doq", "--provider", "adguard", "--proxy", "http://proxy.example:8080"}); err == nil {
		t.Fatal("DoQ accepted an HTTP proxy")
	}
	if _, _, err := parseQueryArgs([]string{"example.com", "--proxy", "socks5://proxy.example:1080"}); err == nil {
		t.Fatal("unsupported proxy scheme was accepted")
	}
}

func TestParseCompareArgsAcceptsSharedProxyForTCPAndHTTPTargets(t *testing.T) {
	options, _, err := parseCompareArgs([]string{
		"example.com", "--target", "doh:cloudflare", "--target", "dot:google", "--proxy", "https://proxy.example:8443",
	})
	if err != nil {
		t.Fatalf("parse compare proxy: %v", err)
	}
	if options.Proxy != "https://proxy.example:8443" {
		t.Fatalf("proxy = %q", options.Proxy)
	}
	if _, _, err := parseCompareArgs([]string{
		"example.com", "--target", "doh:cloudflare", "--target", "doq:adguard", "--proxy", "http://proxy.example:8080",
	}); err == nil {
		t.Fatal("compare accepted a proxy with a QUIC target")
	}
}

func TestParseCompareArgsRejectsDuplicatesAndLimits(t *testing.T) {
	for _, args := range [][]string{
		{"example.com", "--target", "doh:cloudflare", "--target", "doh:cloudflare"},
		{"example.com", "--target", "doh:cloudflare", "--target", "dot:google", "--max-attempts", "1"},
		{"example.com", "--target", "doh:cloudflare", "--target", "dot:google", "--attempt-timeout", "10s", "--timeout", "5s"},
	} {
		if _, _, err := parseCompareArgs(args); err == nil {
			t.Fatalf("parseCompareArgs(%q) succeeded, want error", args)
		}
	}
}

func TestResultExitCodes(t *testing.T) {
	tests := []struct {
		completed bool
		class     string
		want      int
	}{
		{completed: true, want: exitSuccess},
		{class: "internal", want: exitLocal},
		{class: "input", want: exitUsage},
		{class: "transport", want: exitTransport},
		{class: "protocol", want: exitTransport},
		{class: "unsupported", want: exitUnsupported},
	}
	for _, test := range tests {
		var resultError *edns.ErrorInfo
		if test.class != "" {
			resultError = &edns.ErrorInfo{Class: test.class}
		}
		if got := resultExitCode(test.completed, resultError); got != test.want {
			t.Fatalf("resultExitCode(%v, %q) = %d, want %d", test.completed, test.class, got, test.want)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"unknown"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run unknown returned %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "unknown command") || stdout.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func successfulResult(operation, protocol, provider, address string) edns.Result {
	return edns.Result{
		SchemaVersion: 1,
		Operation:     operation,
		Completed:     true,
		Query:         edns.QueryInfo{Name: "example.com", Type: "A"},
		Resolver:      edns.ResolverInfo{Provider: provider, Endpoint: provider + ".example:443", Profile: "test"},
		Transport: edns.TransportInfo{
			Protocol:            protocol,
			Encrypted:           true,
			ServerAuthenticated: true,
			ElapsedMS:           12,
			Bootstrap:           "test_fixture",
		},
		DNS: edns.DNSInfo{
			RCode:      "NOERROR",
			RCodeValue: 0,
			Answers: []edns.AnswerRecord{{
				"name": "example.com", "type": "A", "ttl": float64(60), "address": address,
			}},
		},
	}
}

func validateResultSchema(t *testing.T, document []byte) {
	t.Helper()
	if err := edns.ValidateResultV1JSON(document); err != nil {
		t.Fatalf("result does not validate against result-v1: %v", err)
	}
}
