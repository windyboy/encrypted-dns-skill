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

type capabilitiesResult struct {
	SchemaVersion int               `json:"schema_version"`
	Command       string            `json:"command"`
	Version       string            `json:"version"`
	Capabilities  []edns.Capability `json:"capabilities"`
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
			Capabilities:  edns.Capabilities(),
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

	flags, positionals, err := consumeFlags(args)
	if err != nil {
		return options, 0, err
	}
	for _, flag := range flags {
		switch flag.key {
		case "protocol":
			options.Protocol = strings.ToLower(flag.value)
		case "provider":
			options.Provider = strings.ToLower(flag.value)
		case "method":
			options.Method = strings.ToLower(flag.value)
		case "timeout":
			parsed, err := time.ParseDuration(flag.value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid timeout %q: %w", flag.value, err)
			}
			timeout = parsed
		case "proxy":
			options.Proxy = flag.value
		default:
			return options, 0, fmt.Errorf("unknown query option --%s", flag.key)
		}
	}
	name, recordType, err := parseDomainAndType(positionals, "query")
	if err != nil {
		return options, 0, err
	}
	options.Name = name
	options.RecordType = recordType
	if timeout < 250*time.Millisecond || timeout > 30*time.Second {
		return options, 0, fmt.Errorf("timeout must be between 250ms and 30s")
	}
	if !edns.IsSupportedRecordType(options.RecordType) {
		return options, 0, fmt.Errorf("unsupported record type %q", options.RecordType)
	}
	if !edns.KnownProtocol(options.Protocol) {
		return options, 0, fmt.Errorf("unknown protocol %q", options.Protocol)
	}
	if _, err := edns.FindProvider(options.Provider); err != nil {
		return options, 0, err
	}
	if err := edns.ValidateHTTPMethod(options.Protocol, options.Method); err != nil {
		if options.Method != "get" && options.Method != "post" {
			return options, 0, fmt.Errorf("DoH method must be get or post")
		}
		return options, 0, fmt.Errorf("--method applies only to DoH and DoH3")
	}
	if err := edns.ValidateProxyURL(options.Proxy); err != nil {
		return options, 0, err
	}
	if options.Proxy != "" && !edns.ProxySupportedForProtocol(options.Protocol) {
		return options, 0, fmt.Errorf("--proxy applies only to DoH and DoT")
	}
	return options, timeout, nil
}

func parseCompareArgs(args []string) (edns.CompareOptions, time.Duration, error) {
	options := edns.CompareOptions{RecordType: "A", AttemptTimeout: 5 * time.Second, MaxAttempts: 4}
	totalTimeout := 30 * time.Second
	seenTargets := map[string]bool{}

	flags, positionals, err := consumeFlags(args)
	if err != nil {
		return options, 0, err
	}
	for _, flag := range flags {
		switch flag.key {
		case "target":
			target, err := parseCompareTarget(flag.value)
			if err != nil {
				return options, 0, err
			}
			identity := target.Protocol + ":" + target.Provider + ":" + target.Method
			if seenTargets[identity] {
				return options, 0, fmt.Errorf("duplicate comparison target %q", flag.value)
			}
			seenTargets[identity] = true
			options.Targets = append(options.Targets, target)
		case "timeout":
			parsed, err := time.ParseDuration(flag.value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid timeout %q: %w", flag.value, err)
			}
			totalTimeout = parsed
		case "attempt-timeout":
			parsed, err := time.ParseDuration(flag.value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid attempt timeout %q: %w", flag.value, err)
			}
			options.AttemptTimeout = parsed
		case "max-attempts":
			parsed, err := strconv.Atoi(flag.value)
			if err != nil {
				return options, 0, fmt.Errorf("invalid max attempts %q", flag.value)
			}
			options.MaxAttempts = parsed
		case "proxy":
			options.Proxy = flag.value
		default:
			return options, 0, fmt.Errorf("unknown compare option --%s", flag.key)
		}
	}

	name, recordType, err := parseDomainAndType(positionals, "compare")
	if err != nil {
		return options, 0, err
	}
	options.Name = name
	options.RecordType = recordType
	if !edns.IsSupportedRecordType(options.RecordType) {
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
	if err := edns.ValidateProxyURL(options.Proxy); err != nil {
		return options, 0, err
	}
	if options.Proxy != "" {
		for _, target := range options.Targets {
			if !edns.ProxySupportedForProtocol(target.Protocol) {
				return options, 0, fmt.Errorf("--proxy cannot be used with %s comparison targets", target.Protocol)
			}
		}
	}
	return options, totalTimeout, nil
}

type flagValue struct {
	key, value string
}

func consumeFlags(args []string) ([]flagValue, []string, error) {
	positionals := make([]string, 0, 2)
	flags := make([]flagValue, 0, len(args))
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
				return nil, nil, fmt.Errorf("--%s requires a value", key)
			}
			value = args[index]
		}
		flags = append(flags, flagValue{key: key, value: value})
	}
	return flags, positionals, nil
}

func parseDomainAndType(positionals []string, command string) (string, string, error) {
	if len(positionals) < 1 || len(positionals) > 2 {
		return "", "", fmt.Errorf("%s requires a domain and optional record type", command)
	}
	recordType := "A"
	if len(positionals) == 2 {
		recordType = strings.ToUpper(positionals[1])
	}
	return positionals[0], recordType, nil
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
	if !edns.KnownProtocol(target.Protocol) {
		return target, fmt.Errorf("unknown protocol %q", target.Protocol)
	}
	if _, err := edns.FindProvider(target.Provider); err != nil {
		return target, err
	}
	if err := edns.ValidateHTTPMethod(target.Protocol, target.Method); err != nil {
		if target.Method != "get" && target.Method != "post" {
			return target, fmt.Errorf("target method must be get or post")
		}
		return target, fmt.Errorf("GET method applies only to DoH and DoH3 targets")
	}
	return target, nil
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
	fmt.Fprintln(writer, "usage: ednsdiag <query|probe> <domain> [type] [--protocol doh|dot|doq|doh3|dnscrypt|odoh|anonymized-dnscrypt] [--provider cloudflare|google|quad9|adguard] [--method post|get] [--proxy http://host:port] [--timeout 5s]")
}

func writeCompareUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: ednsdiag compare <domain> [type] --target protocol:provider[:method] --target protocol:provider[:method] [--proxy http://host:port] [--attempt-timeout 5s] [--timeout 30s] [--max-attempts 4]")
}
