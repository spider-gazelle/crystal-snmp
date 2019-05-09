require "./helper"

describe SNMP do
  it "should parse a SNMP V1 Trap" do
    b = Bytes[48, 129, 139, 2, 1, 0, 4, 11, 53, 114, 78, 84, 103, 33, 112, 109, 49, 99, 107, 164, 121, 6, 8, 43, 6, 1, 6, 3, 1, 1, 5, 64, 4, 10, 230, 254, 28, 2, 1, 3, 2, 1, 0, 67, 4, 14, 162, 200, 72, 48, 91, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 1, 26, 2, 1, 26, 48, 35, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 2, 26, 4, 21, 71, 105, 103, 97, 98, 105, 116, 69, 116, 104, 101, 114, 110, 101, 116, 49, 47, 48, 47, 49, 57, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 3, 26, 2, 1, 6, 48, 18, 6, 12, 43, 6, 1, 4, 1, 9, 2, 2, 1, 1, 20, 26, 4, 2, 117, 112]
    io = IO::Memory.new(b)

    snmp = SNMP.parse(io.read_bytes(ASN1::BER))
    snmp.version.should eq(SNMP::Version::V1)
    snmp.request.should eq(SNMP::Request::V1_Trap)
    snmp.community.should eq("5rNTg!pm1ck")

    snmp.varbinds.map(&.oid).should eq(["1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.2.26", "1.3.6.1.2.1.2.2.1.3.26", "1.3.6.1.4.1.9.2.2.1.1.20.26"])
    snmp.expects_response?.should eq(false)
    snmp.trap?.should eq(true)

    snmp_pdu = snmp.pdu
    if snmp_pdu.is_a?(SNMP::V1Trap)
      snmp_pdu.oid.should eq("1.3.6.1.6.3.1.1.5")
      snmp_pdu.agent_address.should eq("10.230.254.28")
      snmp_pdu.generic_trap.should eq(SNMP::GenericTrap::LinkUp)
      snmp_pdu.specific_trap.should eq(0)
      snmp_pdu.time_ticks.should eq(245549128)

      snmp_pdu.varbinds.map(&.oid).should eq(["1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.2.26", "1.3.6.1.2.1.2.2.1.3.26", "1.3.6.1.4.1.9.2.2.1.1.20.26"])
    else
      raise "should be a v1 trap pdu"
    end
  end

  it "should be able to write a SNMP V1 responses" do
    b = Bytes[0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06,
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02, 0x01, 0x26, 0x02,
      0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b,
      0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12, 0x2b, 0x06, 0x01,
      0x04, 0x01, 0x8f, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b,
      0x02, 0x02, 0x01]
    io = IO::Memory.new(b)

    snmp = SNMP.parse(io.read_bytes(ASN1::BER))
    snmp.version.should eq(SNMP::Version::V1)
    snmp.community.should eq("public")

    io2 = IO::Memory.new
    io2.write_bytes snmp

    io2.to_slice.should eq(b)
  end

  it "should be able to parse a SNMP v3 probe and responses" do
    # Parse probe request
    bytes = "303e020103301102042841a2ed020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e02042c52f7770201000201003000"
    io = IO::Memory.new(bytes.hexbytes)
    snmp = SNMP.parse(io.read_bytes(ASN1::BER))

    # Ensure it serialises to the same value
    io2 = IO::Memory.new
    io2.write_bytes snmp
    io2.to_slice.should eq(io.to_slice)

    # Parse the probe response
    bytes = "3068020103301102042841a2ed020300ffe3040100020103041d301b040c0000000000000000000000020201040202034d0400040004003031040c0000000000000000000000020400a81f02042c52f7770201000201003011300f060a2b060106030f01010400410105"
    io = IO::Memory.new(bytes.hexbytes)
    snmp = SNMP.parse(io.read_bytes(ASN1::BER))

    io2 = IO::Memory.new
    io2.write_bytes snmp
    io2.to_slice.should eq(io.to_slice)

    # Parse additional requests
    bytes = "3069020103301102042841a2ec020300ffe304010402010304243022040c0000000000000000000000020201040202034d0407617574686d643504000400302b040c0000000000000000000000020400a11902042c52f776020100020100300b300906052b060102010500"
    io = IO::Memory.new(bytes.hexbytes)
    snmp = SNMP.parse(io.read_bytes(ASN1::BER))

    io2 = IO::Memory.new
    io2.write_bytes snmp
    io2.to_slice.should eq(io.to_slice)

    bytes = "306c020103301102042841a2ec020300ffe304010002010304243022040c0000000000000000000000020201040202034d0407617574686d643504000400302e040c0000000000000000000000020400a81c0201000201000201003011300f060a2b060106030f01010100410103"
    io = IO::Memory.new(bytes.hexbytes)
    snmp = SNMP.parse(io.read_bytes(ASN1::BER))

    io2 = IO::Memory.new
    io2.write_bytes snmp
    io2.to_slice.should eq(io.to_slice)
  end

  it "should be able to generate a probe request" do
    bytes = "303e020103301102042841a2ed020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e02042c52f7770201000201003000"

    message = SNMP::V3::Session.new("authmd5").engine_validation_probe
    message.pdu.request_id = 743634807
    message.id = 675390189
    io = IO::Memory.new
    io.write_bytes message

    io.to_slice.should eq(bytes.hexbytes)
  end

  it "should be able to parse and serialise a message" do
    data = "3082013802010330110204009e5d1a020300ffe3040101020103042f302d040d80001f888059dc486145a2632202010802020ab90405706970706f040c9fa0795c5587c2b88c90897204003081ee040d80001f888059dc486145a263220400a281da02042c180dbc0201000201003081cb30819506082b0601020101010004818844617277696e2069642d6573742e6c6f63616c20382e382e302044617277696e204b65726e656c2056657273696f6e20382e382e303a20467269205365702020382031373a31383a35372050445420323030363b20726f6f743a786e752d3739322e31322e362e6f626a7e312f52454c454153455f50504320506f776572204d6163696e746f7368300f06082b0601020101030043030430d3300f06082b060102010403004103029945300f06082b06010201040a004103020d8b"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP.parse(test)
    io = IO::Memory.new
    io.write_bytes snmp
    io.to_slice.hexstring.should eq(data)
  end

  it "should sign a request" do
    engine_id = "000000000000000000000002"
    password = "maplesyrup"
    security = SNMP::V3::Security.new("username", engine_id, SNMP::V3::Security::AuthProtocol::MD5, password, priv_password: "maplesyrup")

    message = SNMP::V3::Session.new("authmd5").engine_validation_probe
    message.pdu.request_id = 743634807
    message.id = 675390189

    message.sign(security)
    message.security_params.auth_param.hexstring.should eq("c16f59f8f047b80b8c2cf950")
  end

  it "should be able to validate a request" do
    security = SNMP::V3::Security.new("pippo", auth_password: "pippoxxx")

    data = "3082013802010330110204009e5d1a020300ffe3040101020103042f302d040d80001f888059dc486145a2632202010802020ab90405706970706f040c9fa0795c5587c2b88c90897204003081ee040d80001f888059dc486145a263220400a281da02042c180dbc0201000201003081cb30819506082b0601020101010004818844617277696e2069642d6573742e6c6f63616c20382e382e302044617277696e204b65726e656c2056657273696f6e20382e382e303a20467269205365702020382031373a31383a35372050445420323030363b20726f6f743a786e752d3739322e31322e362e6f626a7e312f52454c454153455f50504320506f776572204d6163696e746f7368300f06082b0601020101030043030430d3300f06082b060102010403004103029945300f06082b06010201040a004103020d8b"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children)
    existing, new_sig = snmp.sign(security)

    new_sig.should eq(existing)
  end
end
