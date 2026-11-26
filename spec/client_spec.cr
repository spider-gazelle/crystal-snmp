require "./helper"

private class SequentialRequestSession < SNMP::Session
  @last_request_id = 0

  def get(oid : String)
    @last_request_id += 1
    super(oid, @last_request_id)
  end
end

private def walk_oids(client : SNMP::Client, request : SNMP::Request, base : String)
  messages = request.get_bulk? ? client.bulk_walk(base) : client.walk(base)
  messages.map(&.oid)
end

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
    script = ->(agent : LoopbackAgent) do
      request, peer = agent.receive
      request.request.should eq(SNMP::Request::Set)
      agent.reply(request, peer)
    end

    value = "x" * 1024
    with_loopback_client(script) do |client|
      client.socket.buffer_size = 128
      client.set("1.3.6.1.4.1.8072.999.0", value).value.get_string.should eq(value)
    end
  end

  it "discards a duplicate reply from an earlier request on the same socket" do
    first_oid = "1.3.6.1.2.1.1.1.0"
    second_oid = "1.3.6.1.2.1.1.5.0"
    script = ->(agent : LoopbackAgent) do
      first, first_peer = agent.receive
      agent.reply(first, first_peer, [SNMP::VarBind.from_value(first.oid, "description")])

      second, second_peer = agent.receive
      second_peer.should eq(first_peer)
      agent.reply(first, second_peer, [SNMP::VarBind.from_value(first.oid, "description")])
      agent.reply(second, second_peer, [SNMP::VarBind.from_value(second.oid, "hostname")])
    end

    with_loopback_client(script, session: SequentialRequestSession.new) do |client|
      client.socket.read_timeout = 1.second
      client.get(first_oid).value.get_string.should eq("description")
      response = client.get(second_oid)
      response.oid.should eq(second_oid)
      response.value.get_string.should eq("hostname")
      client.socket.read_timeout.should eq(1.second)
    end
  end

  it "opens a fresh socket for the next request after a timeout or close" do
    oid = "1.3.6.1.2.1.1.5.0"
    script = ->(agent : LoopbackAgent) do
      agent.receive
      2.times do
        request, peer = agent.receive
        agent.reply(request, peer, [SNMP::VarBind.from_value(request.oid, "hostname")])
      end
    end

    with_loopback_client(script, timeout: 1) do |client|
      initial_socket = client.socket
      expect_raises(SNMP::TimeoutError) { client.get(oid) }
      initial_socket.closed?.should be_true

      client.get(oid).value.get_string.should eq("hostname")
      second_socket = client.socket
      second_socket.should_not be(initial_socket)
      client.close
      second_socket.closed?.should be_true

      client.get(oid).value.get_string.should eq("hostname")
      client.socket.should_not be(second_socket)
    end
  end

  it "exchanges multi-varbind Get, GetNext, GetBulk and Set requests" do
    bases = ["1.3.6.1.2.1.1.4", "1.3.6.1.2.1.1.6"]
    oids = bases.map { |oid| "#{oid}.0" }
    values = ["contact", "location"]
    bindings = oids.zip(values).map { |oid, value| SNMP::VarBind.from_value(oid, value) }
    script = ->(agent : LoopbackAgent) do
      get, peer = agent.receive
      get.request.should eq(SNMP::Request::Get)
      get.varbinds.map(&.oid).should eq(oids)
      agent.reply(get, peer, bindings)

      get_next, peer = agent.receive
      get_next.request.should eq(SNMP::Request::GetNext)
      get_next.varbinds.map(&.oid).should eq(bases)
      agent.reply(get_next, peer, bindings)

      next_one, peer = agent.receive
      next_one.request.should eq(SNMP::Request::GetNext)
      next_one.varbinds.map(&.oid).should eq([bases.first])
      agent.reply(next_one, peer, [bindings.first])

      bulk, peer = agent.receive
      bulk.request.should eq(SNMP::Request::GetBulk)
      bulk.varbinds.map(&.oid).should eq(bases)
      bulk.non_repeaters.should eq(1)
      bulk.max_repetitions.should eq(2)
      agent.reply(bulk, peer, bindings)

      set, peer = agent.receive
      set.request.should eq(SNMP::Request::Set)
      set.varbinds.map(&.oid).should eq(oids)
      set.varbinds.map(&.value.get_string).should eq(values)
      agent.reply(set, peer)
    end

    with_loopback_client(script) do |client|
      client.get(oids).varbinds.map(&.value.get_string).should eq(values)
      client.get_next(bases).varbinds.map(&.oid).should eq(oids)
      client.get_next(bases.first).oid.should eq(oids.first)
      client.get_bulk(bases, non_repeaters: 1, max_repetitions: 2).varbinds.map(&.oid).should eq(oids)
      client.set(oids.zip(values).to_h).varbinds.map(&.value.get_string).should eq(values)
    end
  end

  {SNMP::Request::GetNext, SNMP::Request::GetBulk}.each do |type|
    describe "#{type} walk termination" do
      base = "1.3.6.1.2.1.2.2.1.1"
      first_oid = "#{base}.9"
      second_oid = "#{base}.10"

      it "returns an empty result for a response with no varbinds" do
        script = ->(agent : LoopbackAgent) do
          request, peer = agent.receive
          request.request.should eq(type)
          agent.reply(request, peer, [] of SNMP::VarBind)
        end
        with_loopback_client(script) { |client| walk_oids(client, type, base).should be_empty }
      end

      it "advances in numeric OID order and stops at endOfMibView" do
        script = ->(agent : LoopbackAgent) do
          request, peer = agent.receive
          request.request.should eq(type)
          request.oid.should eq(base)
          agent.reply(request, peer, [SNMP::VarBind.from_value(first_oid, 9)])

          request, peer = agent.receive
          request.oid.should eq(first_oid)
          agent.reply(request, peer, [SNMP::VarBind.from_value(second_oid, 10)])

          request, peer = agent.receive
          request.oid.should eq(second_oid)
          end_of_mib = SNMP::VarBind.new(second_oid, 2)
          end_of_mib.value.tag_class = ASN1::BER::TagClass::ContextSpecific
          agent.reply(request, peer, [end_of_mib])
        end
        with_loopback_client(script) { |client| walk_oids(client, type, base).should eq([first_oid, second_oid]) }
      end

      {"repeated" => second_oid, "decreasing" => first_oid}.each do |direction, next_oid|
        it "raises a client error for a #{direction} OID" do
          script = ->(agent : LoopbackAgent) do
            request, peer = agent.receive
            request.request.should eq(type)
            agent.reply(request, peer, [SNMP::VarBind.from_value(second_oid, 10)])

            request, peer = agent.receive
            request.oid.should eq(second_oid)
            agent.reply(request, peer, [SNMP::VarBind.from_value(next_oid, 9)])
          end
          with_loopback_client(script) do |client|
            expect_raises(SNMP::Client::Error, /non-increasing OID/) { walk_oids(client, type, base) }
          end
        end
      end
    end
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
