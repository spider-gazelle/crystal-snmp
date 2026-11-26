# Raw-socket SNMPv3 exchange: engine discovery, auth+priv, response validation.
# In your project: require "snmp"
require "../src/snmp"

# Connect to the agent
socket = UDPSocket.new
socket.connect("localhost", 161)
socket.read_timeout = 3.seconds

receive_message = -> do
  packet, _ = socket.receive(65_507)
  ber = ASN1::BER.new
  ber.max_content_length = packet.bytesize
  ber.read(IO::Memory.new(packet))
  ber
end

# Session with authentication and privacy (see AuthProtocol / PrivacyProtocol
# for the supported algorithms, incl. SHA-2 and AES-256)
session = SNMP::V3::Session.new(
  "usr-md5-aes", "authkey1", "privkey1",
  priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES
)

# Discover the engine id / boots / time (required before authenticated requests;
# also drives periodic revalidation of the RFC 3414 time window)
if session.must_revalidate?
  socket.send(session.engine_validation_probe.to_ber.to_slice)
  session.validate receive_message.call
end

# Build the request, then prepare it (encrypt + sign) for transmission
request = session.get("1.3.6.1.2.1.1.4.0")
socket.send(session.prepare(request).to_slice)

# Parse the response: the HMAC is verified and the time window enforced.
# Still check that it answers *this* request before trusting the values.
response = session.parse(receive_message.call)
raise "response-id mismatch" unless response.request_id == request.request_id
raise "agent error: #{response.error_status}" unless response.error_status.no_error?

puts response.value.get_string
socket.close
