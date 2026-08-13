package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
	for _, item := range result.Capabilities {
		if item.Status == "available" {
			t.Fatalf("foundation build must not advertise %s as available", item.Protocol)
		}
	}
}

func TestReservedCommandIsNotImplemented(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"query"}, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("run query returned %d, want 4", code)
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q, want not implemented message", stderr.String())
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
