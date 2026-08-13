package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/windyboy/encrypted-dns-skill/internal/edns"
)

const version = "0.1.0-dev"

const (
	exitSuccess     = 0
	exitLocal       = 1
	exitUsage       = 2
	exitTransport   = 3
	exitUnsupported = 4
)

var (
	runQuery   = edns.Query
	runProbe   = edns.Probe
	runCompare = edns.Compare
)

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
				{Protocol: "doq", Status: "available", Standard: "RFC 9250", Note: "RFC wire format over dedicated QUIC streams"},
				{Protocol: "doh3", Status: "available", Standard: "RFC 8484 over HTTP/3", Note: "RFC wire format over HTTP/3 GET or POST"},
				{Protocol: "dnscrypt", Status: "available", Standard: "DNSCrypt protocol specification", Note: "DNSCrypt v2 with authenticated resolver certificates"},
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

	case "query", "probe":
		options, timeout, err := parseQueryArgs(args[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			writeQueryUsage(stderr)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var result edns.Result
		if args[0] == "probe" {
			result = runProbe(ctx, options)
		} else {
			result = runQuery(ctx, options)
		}
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
		return resultExitCode(result.Completed, result.Error)

	case "compare":
		options, timeout, err := parseCompareArgs(args[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			writeCompareUsage(stderr)
			return exitUsage
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		result := runCompare(ctx, options)
		if code := writeJSON(stdout, stderr, result); code != 0 {
			return code
		}
		return resultExitCode(result.Completed, result.Error)

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
	if !knownRecordType(options.RecordType) {
		return options, 0, fmt.Errorf("unsupported record type %q", options.RecordType)
	}
	if !knownProtocol(options.Protocol) {
		return options, 0, fmt.Errorf("unknown protocol %q", options.Protocol)
	}
	if _, err := edns.FindProvider(options.Provider); err != nil {
		return options, 0, err
	}
	if options.Method != "get" && options.Method != "post" {
		return options, 0, fmt.Errorf("DoH method must be get or post")
	}
	if options.Protocol != "doh" && options.Protocol != "doh3" && options.Method != "post" {
		return options, 0, fmt.Errorf("--method applies only to DoH and DoH3")
	}
	return options, timeout, nil
}

func parseCompareArgs(args []string) (edns.CompareOptions, time.Duration, error) {
	options := edns.CompareOptions{RecordType: "A", AttemptTimeout: 5 * time.Second, MaxAttempts: 4}
	totalTimeout := 30 * time.Second
	positionals := make([]string, 0, 2)
	seenTargets := map[string]bool{}

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
		case "target":
			target, err := parseCompareTarget(value)
			if err != nil {
				return options, 0, err
			}
			identity := target.Protocol + ":" + target.Provider + ":" + target.Method
			if seenTargets[identity] {
				return options, 0, fmt.Errorf("duplicate comparison target %q", value)
			}
			seenTargets[identity] = true
			options.Targets = append(options.Targets, target)
		case "timeout":
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid timeout %q: %w", value, err)
			}
			totalTimeout = parsed
		case "attempt-timeout":
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid attempt timeout %q: %w", value, err)
			}
			options.AttemptTimeout = parsed
		case "max-attempts":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid max attempts %q", value)
			}
			options.MaxAttempts = parsed
		default:
			return options, 0, fmt.Errorf("unknown compare option --%s", key)
		}
	}

	if len(positionals) < 1 || len(positionals) > 2 {
		return options, 0, fmt.Errorf("compare requires a domain and optional record type")
	}
	options.Name = positionals[0]
	if len(positionals) == 2 {
		options.RecordType = strings.ToUpper(positionals[1])
	}
	if !knownRecordType(options.RecordType) {
		return options, 0, fmt.Errorf("unsupported record type %q", options.RecordType)
	}
	if len(options.Targets) < 2 {
		return options, 0, fmt.Errorf("compare requires at least two --target values")
	}
	if options.MaxAttempts < 2 || options.MaxAttempts > 8 {
		return options, 0, fmt.Errorf("max attempts must be between 2 and 8")
	}
	if len(options.Targets) > options.MaxAttempts {
		return options, 0, fmt.Errorf("comparison targets exceed max attempts")
	}
	if totalTimeout < 250*time.Millisecond || totalTimeout > 60*time.Second {
		return options, 0, fmt.Errorf("compare timeout must be between 250ms and 60s")
	}
	if options.AttemptTimeout < 250*time.Millisecond || options.AttemptTimeout > 30*time.Second {
		return options, 0, fmt.Errorf("attempt timeout must be between 250ms and 30s")
	}
	if options.AttemptTimeout > totalTimeout {
		return options, 0, fmt.Errorf("attempt timeout cannot exceed compare timeout")
	}
	return options, totalTimeout, nil
}

func parseCompareTarget(value string) (edns.CompareTarget, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return edns.CompareTarget{}, fmt.Errorf("target %q must be protocol:provider[:method]", value)
	}
	target := edns.CompareTarget{Protocol: strings.ToLower(parts[0]), Provider: strings.ToLower(parts[1]), Method: "post"}
	if len(parts) == 3 {
		target.Method = strings.ToLower(parts[2])
	}
	if !knownProtocol(target.Protocol) {
		return target, fmt.Errorf("unknown protocol %q", target.Protocol)
	}
	if _, err := edns.FindProvider(target.Provider); err != nil {
		return target, err
	}
	if target.Method != "get" && target.Method != "post" {
		return target, fmt.Errorf("target method must be get or post")
	}
	if target.Protocol != "doh" && target.Protocol != "doh3" && target.Method != "post" {
		return target, fmt.Errorf("GET method applies only to DoH and DoH3 targets")
	}
	return target, nil
}

func knownProtocol(protocol string) bool {
	switch protocol {
	case "doh", "dot", "doq", "doh3", "dnscrypt", "odoh", "anonymized-dnscrypt":
		return true
	default:
		return false
	}
}

func knownRecordType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR", "HTTPS", "SVCB":
		return true
	default:
		return false
	}
}

func resultExitCode(completed bool, resultError *edns.ErrorInfo) int {
	if completed {
		return exitSuccess
	}
	if resultError == nil {
		return exitLocal
	}
	switch resultError.Class {
	case "internal":
		return exitLocal
	case "input":
		return exitUsage
	case "unsupported":
		return exitUnsupported
	case "transport", "protocol":
		return exitTransport
	default:
		return exitLocal
	}
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
	fmt.Fprintln(writer, "usage: ednsdiag <query|probe> <domain> [type] [--protocol doh|dot|doq|doh3|dnscrypt|odoh|anonymized-dnscrypt] [--provider cloudflare|google|quad9|adguard] [--method post|get] [--timeout 5s]")
}

func writeCompareUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ednsdiag compare <domain> [type] --target protocol:provider[:method] --target protocol:provider[:method] [--attempt-timeout 5s] [--timeout 30s] [--max-attempts 4]")
}
