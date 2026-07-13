# SNMP Support for Crystal Lang

[![CI](https://github.com/spider-gazelle/crystal-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/crystal-snmp/actions/workflows/ci.yml)

An SNMP library for Crystal — v1, v2c and v3, usable on both the manager and
agent side.

* SNMPv3 USM with MD5 / SHA-1 / SHA-2 authentication (RFC 7860) and
  DES / AES-128/192/256 privacy, engine discovery, RFC 3414 time-window
  enforcement and automatic resync on `usmStats` Reports
* Get / GetNext / GetBulk / Set, single or multi-varbind, subtree walks
* Typed SET values (`Counter32`, `Gauge32`, `TimeTicks`, `Counter64`,
  `IpAddress`, `Opaque`, `OID`)
* Trap / Inform building, sending and parsing (v1, v2c)
* A typed exception hierarchy rooted at `SNMP::Error`

## Installation

Add the shard to your `shard.yml`:

```yaml
dependencies:
  snmp:
    github: spider-gazelle/crystal-snmp
```

## Usage

The code blocks below are kept in [`examples/`](examples/) and type-checked by
the CI, so they stay in sync with the library.

### High-level client

`SNMP::Client` drives the socket for you (reused across requests) — one client
per fiber. From [`examples/client.cr`](examples/client.cr):

```crystal
require "snmp"

# ---- v2c ----
client = SNMP::Client.new("localhost", community: "public")

# Single get: the shortcut accessors read the first varbind
message = client.get("1.3.6.1.2.1.1.4.0")
puts message.value.get_string

# Multi-varbind get: one round-trip for several OIDs
message = client.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"])
message.varbinds.each { |varbind| puts "#{varbind.oid} => #{varbind.value.get_string}" }

# Walk a subtree (GetNext based); the block form streams
client.walk("1.3.6.1.2.1.1.9.1.3") do |msg|
  puts "#{msg.oid} => #{msg.value.get_string}"
end

# Bulk walk (GetBulk based, fewer round-trips); yields each VarBind
client.bulk_walk("1.3.6.1.2.1.2.2.1.2", max_repetitions: 25) do |varbind|
  puts "#{varbind.oid} => #{varbind.value.get_string}"
end

# Set values — Crystal primitives or typed SNMP values
client.set("1.3.6.1.2.1.1.6.0", "server room")
client.set("1.3.6.1.2.1.1.3.0", SNMP::TimeTicks.new(12_345_u32))

# Multi-varbind set: one SetRequest for several assignments
client.set({
  "1.3.6.1.2.1.1.5.0" => "hostname",
  "1.3.6.1.2.1.1.6.0" => "the location",
})

# Send notifications (community sessions)
client.send_trap_v2("1.3.6.1.4.1.8072.2.3.0.1", uptime: 12_345)
response = client.send_inform("1.3.6.1.4.1.8072.2.3.0.1")
puts response.request # Response (the inform acknowledgement)

# Release the reused UDP socket when done (reconnects transparently if reused)
client.close

# ---- v3 ----
# The client drives engine discovery, HMAC verification, the RFC 3414 time
# window, and auto-resyncs/retries once on a usmStats Report.
security = SNMP::V3::Security.new(
  "usr-sha-aes",
  auth_protocol: SNMP::V3::Security::AuthProtocol::SHA256,
  auth_password: "authkey1",
  priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES256,
  priv_password: "privkey1"
)
v3_client = SNMP::Client.new("localhost", SNMP::V3::Session.new(security))
puts v3_client.get("1.3.6.1.2.1.1.4.0").value.get_string
```

### Raw sockets

When you manage the transport yourself, always check that the response answers
*your* request (response-id) before trusting the values.

SNMPv2c, from [`examples/v2c_raw.cr`](examples/v2c_raw.cr):

```crystal
require "snmp"

# Connect to the agent
socket = UDPSocket.new
socket.connect("localhost", 161)
socket.sync = false
socket.read_timeout = 3.seconds

# Build and send the request
session = SNMP::Session.new(community: "public")
request = session.get("1.3.6.1.2.1.1.4.0")
socket.write_bytes request
socket.flush

# Parse the response, verifying it answers *this* request
response = session.parse(socket.read_bytes(ASN1::BER))
raise "response-id mismatch" unless response.request_id == request.request_id
raise "agent error: #{response.error_status}" unless response.error_status.no_error?

puts response.value.get_string
socket.close
```

SNMPv3, from [`examples/v3_raw.cr`](examples/v3_raw.cr):

```crystal
require "snmp"

# Connect to the agent
socket = UDPSocket.new
socket.connect("localhost", 161)
socket.sync = false
socket.read_timeout = 3.seconds

# Session with authentication and privacy (see AuthProtocol / PrivacyProtocol
# for the supported algorithms, incl. SHA-2 and AES-256)
session = SNMP::V3::Session.new(
  "usr-md5-aes", "authkey1", "privkey1",
  priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES
)

# Discover the engine id / boots / time (required before authenticated requests;
# also drives periodic revalidation of the RFC 3414 time window)
if session.must_revalidate?
  socket.write_bytes session.engine_validation_probe
  socket.flush
  session.validate socket.read_bytes(ASN1::BER)
end

# Build the request, then prepare it (encrypt + sign) for transmission
request = session.get("1.3.6.1.2.1.1.4.0")
socket.write_bytes session.prepare(request)
socket.flush

# Parse the response: the HMAC is verified and the time window enforced.
# Still check that it answers *this* request before trusting the values.
response = session.parse(socket.read_bytes(ASN1::BER))
raise "response-id mismatch" unless response.request_id == request.request_id
raise "agent error: #{response.error_status}" unless response.error_status.no_error?

puts response.value.get_string
socket.close
```

### Setting values

`set` accepts Crystal primitives (`String`, `Int`, `Bool`, `Nil`), the typed
SNMP values (`SNMP::Counter32`, `Gauge32`, `TimeTicks`, `Counter64`,
`IpAddress`, `Opaque`, `OID` — encoded with their proper application tags), a
pre-built `SNMP::VarBind`, or a raw `ASN1::BER` for anything exotic:

```crystal
session.set("1.3.6.1.2.1.1.6.0", "some string value")
session.set("1.3.6.1.2.1.1.3.0", SNMP::TimeTicks.new(34_u32))

# Escape hatch for unsupported encodings
ber = ASN1::BER.new
ber.tag_class = ASN1::BER::TagClass::Application
ber.tag_number = 12
ber.payload = Bytes[1, 2, 3, 4, 5]
session.set("1.3.6.1.2.1.1.3.0", ber)
```

### Extracting response values

The response value is always an `ASN1::BER` (`message.value` — use
`message.varbind` for the whole OID/value pair, or `message.varbinds` for all
of them). Helper methods extract the common types:

* `.get_string`
* `.get_object_id` for SNMP OIDs such as 1.3.6.1.2.1
* `.get_hexstring` for a hex representation of the payload bytes
* `.get_bytes` for the raw byte data
* `.get_boolean`
* `.get_integer` returning an `Int64`

`SNMP.get_unsigned32` / `SNMP.get_unsigned64` decode Counter/Gauge values, and
`VarBind#no_such_object?` / `#no_such_instance?` / `#end_of_mib_view?` detect
the SNMPv2 exception values.

### Errors

Everything the library raises inherits `SNMP::Error`: `SNMP::ParseError`
(malformed wire data), `SNMP::VersionError`, `SNMP::TimeoutError`, and
`SNMP::V3::Security::Error` with `AuthenticationError` /
`NotInTimeWindowError` / `ReportError` for the v3 security machinery.

## Notes on IO

### Writing to sockets

When writing SNMP messages to a socket yourself, buffer the write:

```crystal
socket.sync = false          # buffer…
socket.write_bytes message   # …the message construction writes…
socket.flush                 # …and send one datagram
```

`to_io` writes the message progressively; without buffering each write would
be sent as its own packet and most SNMP agents will not accept fragmented
messages. (`SNMP::Client` handles this for you.)

### Reading from sockets

Whilst you'll probably be OK reading data like `socket.read_bytes(ASN1::BER)`
you should probably be buffering requests based on SNMP PDU max size
(defaulting to 65507 bytes) and throwing away any buffered data that can't be
read after buffering or a short timeout.

## Development

The toolchain is pinned with [mise](https://mise.jdx.dev): `mise install`, then
`mise dev:deps`. The main tasks:

| Task | What it does |
|------|--------------|
| `dev:spec` | deterministic spec suite (offline) |
| `dev:snmpd` + `dev:spec-e2e` | live suite against a local net-snmp agent |
| `dev:check` | format-check + lint + spec + multi-threaded spec |
| `dev:examples` | type-check the README examples |

See [`CLAUDE.md`](CLAUDE.md) for the full task list and spec-tagging
conventions.
