# Raw-socket SNMPv3 exchange: engine discovery, auth+priv, response validation.
# In your project: require "snmp"
require "../src/snmp"

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
