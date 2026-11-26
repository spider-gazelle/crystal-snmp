require "./helper"

describe SNMP::Client do
  describe ".oid_within?" do
    it "matches the base itself and its true children" do
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.1").should be_true
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.1").should be_true
    end

    it "rejects a sibling column that merely shares a string prefix" do
      # column 10 (ifInOctets) is NOT a child of column 1 (ifIndex)
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.10.5", "1.3.6.1.2.1.2.2.1.1").should be_false
    end
  end

  it "exchanges SET messages larger than the socket's stream buffer" do
    server = UDPSocket.new
    server.bind("127.0.0.1", 0)
    server.read_timeout = 3.seconds
    client = SNMP::Client.new("127.0.0.1", port: server.local_address.port)
    client.socket.buffer_size = 128
    agent_result = Channel(Exception?).new(1)

    spawn do
      packet, peer = server.receive(65_507)
      request = SNMP::Session.new.parse(ASN1::BER.from_slice(packet.to_slice))
      response = SNMP::Message.new(request.community, SNMP::Request::Response, request.varbinds, request.request_id)
      server.send(response.to_ber.to_slice, peer)
      agent_result.send(nil)
    rescue ex
      agent_result.send(ex)
    end

    value = "x" * 1024
    response = begin
      client.set("1.3.6.1.4.1.8072.999.0", value)
    rescue ex : SNMP::TimeoutError
      raise agent_result.receive || ex
    end
    response.value.get_string.should eq(value)
    agent_result.receive.should be_nil
  ensure
    client.try(&.close)
    server.try(&.close)
  end

  it "should perform a walk", tags: "e2e" do
    client = SNMP::Client.new(TEST_SNMP_SERVER, port: TEST_SNMP_PORT)
    client.should_not be_nil
    messages = client.walk("1.3.6.1.2.1.1.9.1.3")
    messages.should be_a(Array(SNMP::Message))
    messages.empty?.should be_false
  end

  it "should perform a walk using a block", tags: "e2e" do
    client = SNMP::Client.new(TEST_SNMP_SERVER, port: TEST_SNMP_PORT)
    client.should_not be_nil
    messages = [] of SNMP::Message
    client.walk("1.3.6.1.2.1.1.9.1.3") do |message|
      messages << message
    end
    messages.empty?.should be_false
  end

  it "performs a bulk walk in OID order", tags: "e2e" do
    client = SNMP::Client.new(TEST_SNMP_SERVER, port: TEST_SNMP_PORT)
    base = "1.3.6.1.2.1.1.9.1.3"
    varbinds = client.bulk_walk(base, max_repetitions: 2)

    varbinds.empty?.should be_false
    varbinds.all? { |varbind| SNMP::Client.oid_within?(varbind.oid, base) }.should be_true
    indices = varbinds.map(&.oid.split('.').last.to_i)
    indices.should eq(indices.sort.uniq!)
  ensure
    client.try(&.close)
  end

  it "discovers a live v3 agent and gets a value with AES privacy", tags: "e2e" do
    session = SNMP::V3::Session.new("usr-md5-aes", "authkey1", "privkey1", priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES)
    client = SNMP::Client.new(TEST_SNMP_SERVER, session, port: TEST_SNMP_PORT)
    client.get("1.3.6.1.2.1.1.4.0").value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
  ensure
    client.try(&.close)
  end
end
