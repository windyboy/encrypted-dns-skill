package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
				{Protocol: "doh", Status: "planned", Standard: "RFC 8484"},
				{Protocol: "dot", Status: "planned", Standard: "RFC 7858 and RFC 8310"},
				{Protocol: "doq", Status: "planned", Standard: "RFC 9250"},
				{Protocol: "doh3", Status: "planned", Standard: "RFC 8484 over HTTP/3"},
				{Protocol: "dnscrypt", Status: "planned", Standard: "DNSCrypt protocol specification"},
				{Protocol: "odoh", Status: "research", Standard: "RFC 9230", Note: "No maintained Go dependency has been selected."},
				{Protocol: "anonymized-dnscrypt", Status: "research", Standard: "Anonymized DNSCrypt specification"},
			},
		}

		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(stderr, "encode capabilities: %v\n", err)
			return 1
		}
		return 0

	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version does not accept arguments")
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0

	case "query", "probe", "compare":
		fmt.Fprintf(stderr, "%s is not implemented in %s; run ednsdiag capabilities\n", args[0], version)
		return 4

	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		writeUsage(stderr)
		return 2
	}
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: ednsdiag <capabilities|version|query|probe|compare>")
}
