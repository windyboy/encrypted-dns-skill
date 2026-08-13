package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
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
	if result.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", result.SchemaVersion)
	}
	if result.Command != "capabilities" {
		t.Fatalf("command = %q, want capabilities", result.Command)
	}
	if len(result.Capabilities) == 0 {
		t.Fatal("capabilities list is empty")
	}
	available := map[string]bool{}
	for _, item := range result.Capabilities {
		available[item.Protocol] = item.Status == "available"
	}
	if !available["doh"] || !available["dot"] || !available["doq"] || !available["doh3"] || !available["dnscrypt"] {
		t.Fatalf("DoH, DoT, DoQ, DoH3, and DNSCrypt must be available: %#v", available)
	}
}

func TestReservedCommandIsNotImplemented(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"probe"}, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("run probe returned %d, want 4", code)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q, want not implemented message", stderr.String())
	}
}

func TestParseQueryArgsAllowsInterspersedOptions(t *testing.T) {
	options, timeout, err := parseQueryArgs([]string{"example.com", "MX", "--protocol", "dot", "--provider=quad9", "--timeout", "3s"})
	if err != nil {
		t.Fatalf("parse query args: %v", err)
	}
	if options.Name != "example.com" || options.RecordType != "MX" || options.Protocol != "dot" || options.Provider != "quad9" {
		t.Fatalf("unexpected options: %#v", options)
	}
	if timeout != 3*time.Second {
		t.Fatalf("timeout = %v, want 3s", timeout)
	}
}

func TestParseQueryArgsAllowsQUICProtocols(t *testing.T) {
	for _, protocol := range []string{"doq", "doh3"} {
		t.Run(protocol, func(t *testing.T) {
			options, _, err := parseQueryArgs([]string{"example.com", "A", "--protocol", protocol})
			if err != nil {
				t.Fatalf("parse %s query: %v", protocol, err)
			}
			if options.Protocol != protocol {
				t.Fatalf("protocol = %q, want %q", options.Protocol, protocol)
			}
		})
	}
}

func TestParseQueryArgsAllowsDNSCrypt(t *testing.T) {
	options, _, err := parseQueryArgs([]string{"example.com", "A", "--protocol", "dnscrypt", "--provider", "adguard"})
	if err != nil {
		t.Fatalf("parse DNSCrypt query: %v", err)
	}
	if options.Protocol != "dnscrypt" || options.Provider != "adguard" {
		t.Fatalf("unexpected DNSCrypt options: %#v", options)
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run unknown returned %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q, want unknown command message", stderr.String())
	}
}
