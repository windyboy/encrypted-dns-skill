# Changelog

## 0.1.0 - 2026-08-15

First tagged release. Public CLI commands, `result-v1` JSON, exit codes, and
error strings are unchanged from the untagged `0.1.0-dev` tree.

### Packaging

- CLI `version` and `capabilities.version` report `0.1.0`
- DoH and DoH3 send `User-Agent: ednsdiag/0.1.0`
- `SKILL.md` records `metadata.version: "0.1.0"`
- No precompiled binaries; run or build from the tagged source

### Internals

Behavior-preserving extracts only:

- Shared DoH/DoH3 same-origin HTTPS redirect helper
- Shared CLI flag and domain/type parsers
- `edns.Capabilities()` plus shared validation predicates
- One `result-v1` JSON Schema test helper
- README no longer copies contract tables; the provider matrix remains
- CI test matrix is Ubuntu and macOS; local Windows `go test` remains supported
