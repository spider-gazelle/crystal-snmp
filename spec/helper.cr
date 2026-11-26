require "spec"

{% if compare_versions(Crystal::VERSION, "1.21.0") >= 0 && !flag?(:without_mt) && !flag?(:preview_mt) %}
  if workers = ENV["SNMP_SPEC_WORKERS"]?
    Fiber::ExecutionContext.default.resize(workers.to_i)
  end
{% end %}

TEST_SNMP_SERVER = ENV["TEST_SNMP_SERVER"]? || "localhost"
# Port of the live test agent — the CI starts an unprivileged snmpd on a high port.
TEST_SNMP_PORT = (ENV["TEST_SNMP_PORT"]? || "161").to_i

require "../src/snmp"

class LoopbackAgent
  @socket = UDPSocket.new

  def initialize
    @socket.bind("127.0.0.1", 0)
    @socket.read_timeout = 3.seconds
  end

  def port : Int32
    @socket.local_address.port
  end

  def receive(security : SNMP::V3::Security? = nil)
    packet, peer = @socket.receive(65_507)
    {SNMP.parse(ASN1::BER.from_slice(packet.to_slice), security), peer}
  end

  def send(message : SNMP::Message, peer : Socket::IPAddress)
    send(message.to_ber, peer)
  end

  def send(message : ASN1::BER, peer : Socket::IPAddress)
    @socket.send(message.to_slice, peer)
  end

  def reply(request : SNMP::Message, peer : Socket::IPAddress, varbinds = request.varbinds)
    response = SNMP::Message.new(request.community, SNMP::Request::Response, varbinds, request.request_id, version: request.version)
    send(response, peer)
  end

  def close : Nil
    @socket.close
  end
end

def with_loopback_client(script, *, session = SNMP::Session.new, timeout = 2, &)
  agent = LoopbackAgent.new
  client = SNMP::Client.new("127.0.0.1", session, timeout: timeout, port: agent.port)
  result = Channel(Exception?).new(1)

  spawn do
    script.call(agent)
    result.send(nil)
  rescue ex
    result.send(ex)
  end

  yield client
  if error = result.receive
    raise error
  end
rescue ex : SNMP::TimeoutError
  if results = result
    select
    when error = results.receive
      raise error if error
    else
    end
  end
  raise ex
ensure
  client.try(&.close)
  agent.try(&.close)
end
