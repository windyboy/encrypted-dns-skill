package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/windyboy/encrypted-dns-skill/internal/edns"
)

const version = "0.1.0-dev"

type capability struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Standard string `json:"standard,omitempty"`
	Note     string `json:"note,omitempty"`
}

type capabilitiesResult struct {
	SchemaVersion int          `json:"schema_version"`
	Command       string       `json:"command"`
	Version       string       `json:"version"`
	Capabilities  []capability `json:"capabilities"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}

	switch args[0] {
	case "capabilities":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "capabilities does not accept arguments")
			return 2
		}
		result := capabilitiesResult{
			SchemaVersion: 1,
			Command:       "capabilities",
			Version:       version,
			Capabilities: []capability{
				{Protocol: "doh", Status: "available", Standard: "RFC 8484", Note: "RFC wire format over HTTP GET or POST"},
				{Protocol: "dot", Status: "available", Standard: "RFC 7858 and RFC 8310", Note: "strict PKIX and authentication-domain validation"},
				{Protocol: "doq", Status: "planned", Standard: "RFC 9250"},
				{Protocol: "doh3", Status: "planned", Standard: "RFC 8484 over HTTP/3"},
				{Protocol: "dnscrypt", Status: "planned", Standard: "DNSCrypt protocol specification"},
				{Protocol: "odoh", Status: "research", Standard: "RFC 9230", Note: "No maintained Go dependency has been selected."},
				{Protocol: "anonymized-dnscrypt", Status: "research", Standard: "Anonymized DNSCrypt specification"},
			},
		}
		return writeJSON(stdout, stderr, result)

	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version does not accept arguments")
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0

	case "query":
		options, timeout, err := parseQueryArgs(args[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			writeQueryUsage(stderr)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		result := edns.Query(ctx, options)
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
		if result.Completed {
			return 0
		}
		if result.Error != nil && result.Error.Class == "input" {
			return 2
		}
		return 3

	case "probe", "compare":
		fmt.Fprintf(stderr, "%s is not implemented in %s; run ednsdiag capabilities\n", args[0], version)
		return 4

	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func parseQueryArgs(args []string) (edns.QueryOptions, time.Duration, error) {
	options := edns.QueryOptions{
		RecordType: "A",
		Protocol:   "doh",
		Provider:   "cloudflare",
		Method:     "post",
	}
	timeout := 5 * time.Second
	positionals := make([]string, 0, 2)

	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "--") {
			positionals = append(positionals, argument)
			continue
		}
		key, value, found := strings.Cut(strings.TrimPrefix(argument, "--"), "=")
		if !found {
			index++
			if index >= len(args) {
				return options, 0, fmt.Errorf("--%s requires a value", key)
			}
			value = args[index]
		}
		switch key {
		case "protocol":
			options.Protocol = strings.ToLower(value)
		case "provider":
			options.Provider = strings.ToLower(value)
		case "method":
			options.Method = strings.ToLower(value)
		case "timeout":
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid timeout %q: %w", value, err)
			}
			timeout = parsed
		default:
			return options, 0, fmt.Errorf("unknown query option --%s", key)
		}
	}
	if len(positionals) < 1 || len(positionals) > 2 {
		return options, 0, fmt.Errorf("query requires a domain and optional record type")
	}
	if timeout < 250*time.Millisecond || timeout > 30*time.Second {
		return options, 0, fmt.Errorf("timeout must be between 250ms and 30s")
	}
	options.Name = positionals[0]
	if len(positionals) == 2 {
		options.RecordType = strings.ToUpper(positionals[1])
	}
	if options.Protocol != "doh" && options.Protocol != "dot" {
		return options, 0, fmt.Errorf("protocol %q is not available", options.Protocol)
	}
	if options.Method != "get" && options.Method != "post" {
		return options, 0, fmt.Errorf("DoH method must be get or post")
	}
	if options.Protocol == "dot" && options.Method != "post" {
		return options, 0, fmt.Errorf("--method applies only to DoH")
	}
	return options, timeout, nil
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "encode JSON result: %v\n", err)
		return 1
	}
	return 0
}

func writeUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ednsdiag <capabilities|version|query|probe|compare>")
}

func writeQueryUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ednsdiag query <domain> [type] [--protocol doh|dot] [--provider cloudflare|google|quad9|adguard] [--method post|get] [--timeout 5s]")
}
