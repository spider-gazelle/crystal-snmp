# CLAUDE.md

Guidance for working on this repository.

## What this is

`snmp` is an SNMP library for Crystal (v1 / v2c / v3, manager and agent side). It
builds on [`bindata`](https://github.com/spider-gazelle/bindata) for the ASN.1/BER
wire encoding. The library parses **untrusted network input**, so treat parsing and
crypto code as production-critical: fix the whole class of a bug, encode what the
wire format actually requires, and spec the edge cases.

## Toolchain

The toolchain is pinned with [mise](https://mise.jdx.dev) — Crystal `1.20.2`
(see `mise.toml`). Install it and the dependencies with:

```
mise install      # provisions the pinned Crystal
mise dev:deps     # shards install (also builds bin/ameba)
```

## Common tasks

Run via `mise <task>`:

| Task | What it does |
|------|--------------|
| `dev:deps` | `shards install` (also builds `bin/ameba`) |
| `dev:format` | format `src/` and `spec/` |
| `dev:format-check` | CI formatting gate |
| `dev:ameba` | static analysis |
| `dev:spec` | deterministic spec suite (excludes `e2e` + `legacy`) |
| `dev:snmpd` | run the test SNMP agent on `127.0.0.1:16161` (foreground) |
| `dev:spec-e2e` | live specs against a real server (set `TEST_SNMP_SERVER` / `TEST_SNMP_PORT`) |
| `dev:spec-legacy` | specs needing OpenSSL legacy algorithms (DES) |
| `dev:spec-mt` | deterministic suite multi-threaded (`-Dpreview_mt`, fiber-safety gate) |
| `dev:docs` | build the API docs (fails on doc-comment / compile errors) |
| `dev:examples` | type-check the README examples (`examples/*.cr`) |
| `dev:check` | format-check + ameba + spec + spec-mt in one shot |

On macOS, if `shards` is missing after a fresh Crystal install, run
`mise dev:fix-shards-command` once.

## Spec conventions

Specs are split by tag so the default run is deterministic and offline:

- **untagged** — pure, offline, always run (`dev:spec`, `dev:spec-mt`).
- **`e2e`** — hit a live SNMP server; require `TEST_SNMP_SERVER` (`dev:spec-e2e`).
- **`legacy`** — need an OpenSSL *legacy* provider (DES/`des-cbc`), which modern
  OpenSSL 3.x does not load by default (`dev:spec-legacy`).

Add the matching tag when a new spec depends on the network or on a legacy cipher,
e.g. `it "...", tags: "e2e" do`.

## Conventions

- Anything touching concurrency / fiber-safety must pass `dev:spec-mt` as well.
- Keep `dev:format-check` and `dev:ameba` clean; do not mass-reformat in a targeted change.
- Prefer typed exceptions and idiomatic Crystal (verify stdlib APIs before use).
