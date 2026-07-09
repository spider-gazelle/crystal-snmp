# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- usmHMAC-SHA-2 authentication — `SHA224`, `SHA256`, `SHA384`, `SHA512` (RFC 7860).
- AES-192 and AES-256 privacy, with the Blumenthal localized-key extension for
  short authentication digests.
- Typed error hierarchy rooted at `SNMP::Error`: `ParseError`, `VersionError`,
  `TimeoutError`, and `SNMP::V3::Security::AuthenticationError`.
- mise-based toolchain (pinned Crystal) with `dev:*` tasks, and a deterministic
  spec suite split from `e2e` (live server) and `legacy` (OpenSSL legacy provider)
  tagged specs.

### Changed
- **Breaking:** `PDU#error_index` is now an `Int32` varbind position; the enum
  `SNMP::ErrorIndex` is removed and the real RFC 3416 error-status list is now
  `SNMP::ErrorStatus`.
- **Breaking:** `SNMP::V3::SecurityModel` values realigned to the IANA registry
  (`SNMPv1=1`, `SNMPv2c=2`, `USM=3`, `TSM=4`); the members `User`/`Transport`/`SNMPv2`
  are renamed to `USM`/`TSM`/`SNMPv2c`.
- `SNMP::Client::Error` and `SNMP::V3::Security::Error` now inherit `SNMP::Error`.
- Minimum Crystal version raised to 1.2.0.

### Fixed
- The parser no longer crashes on malformed or truncated datagrams — unknown enum
  values and missing fields raise `SNMP::ParseError` instead of `ArgumentError`/`IndexError`.
- `SNMP.get_unsigned64`/`get_unsigned32` no longer raise on maximal `Counter64`/`Counter32`
  values (9-/5-byte encodings).
- `Client#walk` no longer overruns into sibling OID columns (arc-aware subtree check).
- `Helpers::IfEntry` tolerates `ifType`/`ifAdminStatus`/`ifOperStatus` values outside the enums.
- `V3::ScopedPDU` encodes/decodes `contextName` as an OCTET STRING (was an OID).
- DES encryption no longer appends a spurious PKCS padding block (RFC 3414).
- SNMPv3 read timeouts surface as `SNMP::TimeoutError`.
- `Message.from_io` is repaired; `V3::Message.new` takes a proper `ASN1::BER` argument.
- `crystal tool format --check` and `bin/ameba` pass on current toolchains.
