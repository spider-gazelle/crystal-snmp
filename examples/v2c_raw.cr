# Raw-socket v2c exchange, for when you manage the transport yourself.
# In your project: require "snmp"
require "../src/snmp"

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
