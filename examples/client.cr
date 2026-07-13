# High-level client usage — one `SNMP::Client` per fiber.
# In your project: require "snmp"
require "../src/snmp"

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
