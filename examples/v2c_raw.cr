# Raw-socket v2c exchange, for when you manage the transport yourself.
# In your project: require "snmp"
require "../src/snmp"

# Connect to the agent
socket = UDPSocket.new
socket.connect("localhost", 161)
socket.read_timeout = 3.seconds

# Build and send the request
session = SNMP::Session.new(community: "public")
request = session.get("1.3.6.1.2.1.1.4.0")
socket.send(request.to_ber.to_slice)

# Parse the response, verifying it answers *this* request
packet, _ = socket.receive(65_507)
ber = ASN1::BER.new
ber.max_content_length = packet.bytesize
ber.read(IO::Memory.new(packet))
response = session.parse(ber)
raise "response-id mismatch" unless response.request_id == request.request_id
raise "agent error: #{response.error_status}" unless response.error_status.no_error?

puts response.value.get_string
socket.close
