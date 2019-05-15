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

  it "should be able to validate a MD5 request" do
    security = SNMP::V3::Security.new("pippo", "80001f888059dc486145a26322", auth_password: "pippoxxx")

    data = "3082013802010330110204009e5d1a020300ffe3040101020103042f302d040d80001f888059dc486145a2632202010802020ab90405706970706f040c9fa0795c5587c2b88c90897204003081ee040d80001f888059dc486145a263220400a281da02042c180dbc0201000201003081cb30819506082b0601020101010004818844617277696e2069642d6573742e6c6f63616c20382e382e302044617277696e204b65726e656c2056657273696f6e20382e382e303a20467269205365702020382031373a31383a35372050445420323030363b20726f6f743a786e752d3739322e31322e362e6f626a7e312f52454c454153455f50504320506f776572204d6163696e746f7368300f06082b0601020101030043030430d3300f06082b060102010403004103029945300f06082b06010201040a004103020d8b"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children)
    existing, new_sig = snmp.sign(security)

    new_sig.should eq(existing)
  end

  it "should be able to validate a SHA1 request" do
    security = SNMP::V3::Security.new("pippo3", "80001f888059dc486145a26322", auth_protocol: SNMP::V3::Security::AuthProtocol::SHA, auth_password: "pippoxxx")

    data = "308201390201033011020445b64b08020300ffe30401010201030430302e040d80001f888059dc486145a2632202010802020aba0406706970706f33040c2f45f36ffc9ebcbedc95487804003081ee040d80001f888059dc486145a263220400a281da02046db720550201000201003081cb30819506082b0601020101010004818844617277696e2069642d6573742e6c6f63616c20382e382e302044617277696e204b65726e656c2056657273696f6e20382e382e303a20467269205365702020382031373a31383a35372050445420323030363b20726f6f743a786e752d3739322e31322e362e6f626a7e312f52454c454153455f50504320506f776572204d6163696e746f7368300f06082b060102010103004303043129300f06082b060102010403004103029945300f06082b06010201040a004103020d8b"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children)
    existing, new_sig = snmp.sign(security)

    new_sig.should eq(existing)
  end

  it "should be able to decrypt a MD5 with DES request" do
    security = SNMP::V3::Security.new("pippo", "80001f888059dc486145a26322", auth_password: "pippoxxx", priv_password: "PIPPOxxx")

    data = "3082014a0201033011020430f6f3d5020300ffe304010302010304373035040d80001f888059dc486145a2632202010802020ab90405706970706f040cc366a119e2be15a84f16e29d0408000000087da0625b0481f8d0b44e7e473b4e1864ff7f47c39254b941c8029f76e4ce419da8bd8ea8258e17cb01163cd02bdd22990b38f82cf4d104c543a772131a55d9abca5cdd86c412d724f6fef89480409c52aeee84a6cd1e474196645398473f5b0b863ca1ce67b434bc95d46143eb82c7f1e1b05b90ddeec375b48afbb1e1a500bccdf788459d19403dc56459ecbe82b88e2bb42de019f963a789f50de993557f2e358d9ad26e4eb199cce54b6632d30ab87404c681e4f5115ec14cf2ca37e2e452834b41775850727570f3d85b7e1a6793268dd263442a8de6fb4a2cf70b50a9c6f636ce0736b343371c5d0692da9d19dc720d1bbf082c9f387e78d0b0432002"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children, security)
    session = SNMP::V3::Session.new(security).validate(snmp)

    # Test serialisation
    io = IO::Memory.new
    io.write_bytes session.prepare(snmp)

    # Test decoding of serialised message
    io.rewind
    test = io.read_bytes(ASN1::BER)
    snmp = SNMP::V3::Message.new(test.children, security)
  end

  it "should be able to decrypt a SHA1 with DES request" do
    security = SNMP::V3::Security.new("pippo2", "80001f888059dc486145a26322", auth_protocol: SNMP::V3::Security::AuthProtocol::SHA, auth_password: "pippoxxx", priv_password: "PIPPOxxx")

    data = "3082014b02010330110204655e2122020300ffe304010302010304383036040d80001f888059dc486145a2632202010802020aba0406706970706f32040c55efd50ae247d453ead989270408000000087da062630481f8bde25443f63f33edd14424a9abff75e11c2f771985ce69689cae26ac4382f16f1743efaabcfc3c2fc3bd9c149ac2ee3f9d278bd9478d38b7d9fcb1ddf6bf6ed4ec51dd13c3d9e93c39b63c0a60f75d1ee6c8b470a8a0a1842b7bd408a065b71a97307dbbc5d6ae6ac51d52dce77de64b4afe7d54ccb6f5bd12f7a01d10c4e46c6dc26023d4c787a40f17daeca49ca26ce569ea1be3457e9a7457079382732a83cea8cd3eceff46745183c684a02c69288d1bb3d5d06b6f240c02d6cc81e9494a6922c1375fa9df926e45fcda76b5b3a7c7d280d7e98f46afa5cf174d359cf5d325a551d32133a6f6474f64b7c23a120a6f64815ea3c3e904"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children, security)
    snmp.varbinds[0].value.get_string.should eq("Darwin id-est.local 8.8.0 Darwin Kernel Version 8.8.0: Fri Sep  8 17:18:57 PDT 2006; root:xnu-792.12.6.obj~1/RELEASE_PPC Power Macintosh")
    session = SNMP::V3::Session.new(security).validate(snmp)

    # Test serialisation
    io = IO::Memory.new
    io.write_bytes session.prepare(snmp)
    # io.to_slice.hexstring.size.should eq(data.size)

    # Test decoding of serialised message
    io.rewind
    test = io.read_bytes(ASN1::BER)
    snmp = SNMP::V3::Message.new(test.children, security)
    snmp.varbinds[0].value.get_string.should eq("Darwin id-est.local 8.8.0 Darwin Kernel Version 8.8.0: Fri Sep  8 17:18:57 PDT 2006; root:xnu-792.12.6.obj~1/RELEASE_PPC Power Macintosh")
  end

  it "should be able to decrypt a SHA1 with AES request" do
    # Data from: http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html
    # `snmpwalk -v3 -l authPriv -u usr-sha-aes -a SHA -A authkey1 -x AES -X privkey1 demo.snmplabs.com 1.3.6`
    security = SNMP::V3::Security.new("usr-sha-aes", "80004fb805636c6f75644dab22cc", auth_protocol: SNMP::V3::Security::AuthProtocol::SHA, priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES, auth_password: "authkey1", priv_password: "privkey1")

    data = "3081ea0201033011020478e1aaaa020300ffe3040103020103043f303d040e80004fb805636c6f75644dab22cc020109020306e7d2040b7573722d7368612d616573040cf2fefd4bd5b858414e7950b5040862c4a71169fbea90048190f43ae92699b793e4c5a432500da0c4e0213102d7b44fd2e9a62c830bd918bf150fb2b402bc3f4a2393a33274c4a2de1a10364e8fb8185c0a26cca23f381005b5c3415726beac676f180d519c73730bd02e1a50363ef342ed23c5acb55f90392b882a7117d97cde1bfee2f4b86efc4fb4e8cf5a6379db86db0a0f7dc1c33a1234d8b21b01303b31b3c5f7de225068d9ec"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    snmp = SNMP::V3::Message.new(test.children, security)
  end

  it "should be able to decrypt a MD5 with AES request" do
    # Samples taken from: http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html
    # `snmpwalk -v3 -l authPriv -u usr-md5-aes -a MD5 -A authkey1 -x AES -X privkey1 demo.snmplabs.com 1.3.6`
    security = SNMP::V3::Security.new("usr-md5-aes", "80004fb805636c6f75644dab22cc", auth_protocol: SNMP::V3::Security::AuthProtocol::MD5, priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES, auth_password: "authkey1", priv_password: "privkey1")

    data = "308199020103301102045e6b982a020300ffe3040103020103043f303d040e80004fb805636c6f75644dab22cc02010a020300da3a040b7573722d6d64352d616573040ca949ba86c8137f6481ecaea6040866fe855b232d56060440666408c8821cee8833e9e537099bb3bbd860bbc8ce1fbcf3c4aafce06f0c36a3e5f35fca5e85c4de736e97a155c464ffeb29b338af635107294728bfd398ad0b"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    test = io.read_bytes(ASN1::BER)

    # Test decoding
    snmp = SNMP::V3::Message.new(test.children, security)
    snmp.varbinds[0].value.get_object_id.should eq("1.3.6.1.4.1.8072.3.2.10")

    session = SNMP::V3::Session.new(security).validate(snmp)

    # Test serialisation
    io = IO::Memory.new
    io.write_bytes session.prepare(snmp)
    io.to_slice.hexstring.size.should eq(data.size)

    # Test decoding of serialised message
    io.rewind
    test = io.read_bytes(ASN1::BER)
    snmp = SNMP::V3::Message.new(test.children, security)
    snmp.varbinds[0].value.get_object_id.should eq("1.3.6.1.4.1.8072.3.2.10")
  end

  it "should generate valid MD5 authed requests" do
    # Samples taken from: http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html
    # Monitoring traffic from the `snmpwalk` tool: `snmpwalk -v3 -l auth -u usr-md5-none -a MD5 -A authkey1 -O n demo.snmplabs.com 1.3.6`
    session = SNMP::V3::Session.new("usr-md5-none", "authkey1")

    # Emulate probe response
    data = "3081a6020103301102042c32fc0e020300ffe304010102010304383036040e80004fb805636c6f75644dab22cc02010a0203015e36040c7573722d6d64352d6e6f6e65040c48c4a8a4843a6ad90d7c79fc04003054040e80004fb805636c6f75644dab22cc0400a2400204215f19c00201000201003032303006082b060102010104000424534e4d50204c61626f7261746f726965732c20696e666f40736e6d706c6162732e636f6d"
    io = IO::Memory.new
    io.write data.hexbytes
    io.rewind
    session.validate(io.read_bytes(ASN1::BER))

    # Make a get_next (walk) request
    message = session.get_next("1.3.6.1.2.1.1.4.0", 559880641, 741538831)
    message = session.prepare(message)

    io = IO::Memory.new
    io.write_bytes message

    # Ensure the message matches a known good example request
    output = "308182020103301102042c32fc0f020300ffe304010502010304383036040e80004fb805636c6f75644dab22cc02010a0203015e36040c7573722d6d64352d6e6f6e65040c92aee8e66e14a35e6371b54c04003030040e80004fb805636c6f75644dab22cc0400a11c0204215f19c1020100020100300e300c06082b060102010104000500"
    io.to_slice.hexstring.should eq(output)
  end

  it "should be able to query SNMPLabs with MD5 auth" do
    # Connect to server
    socket = UDPSocket.new
    socket.connect("demo.snmplabs.com", 161)
    socket.sync = false

    # Setup session
    session = SNMP::V3::Session.new("usr-md5-none", "authkey1")
    if session.must_revalidate?
      socket.write_bytes session.engine_validation_probe
      socket.flush
      session.validate socket.read_bytes(ASN1::BER)
    end

    # Make request
    ber = session.prepare(session.get("1.3.6.1.2.1.1.4.0"))
    socket.write_bytes ber
    socket.flush

    # Process response
    response = session.parse(socket.read_bytes(ASN1::BER))
    response.value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
  end

  it "should be able to query SNMPLabs with MD5 and AES auth" do
    # Connect to server
    socket = UDPSocket.new
    socket.connect("demo.snmplabs.com", 161)
    socket.sync = false

    # Setup session
    session = SNMP::V3::Session.new("usr-md5-aes", "authkey1", "privkey1", priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES)
    if session.must_revalidate?
      socket.write_bytes session.engine_validation_probe
      socket.flush
      session.validate socket.read_bytes(ASN1::BER)
    end

    # Make request
    ber = session.prepare(session.get("1.3.6.1.2.1.1.4.0"))
    socket.write_bytes ber
    socket.flush

    # Process response
    response = session.parse(socket.read_bytes(ASN1::BER))
    response.value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
  end

  it "should be able to query SNMPLabs with MD5 and DES auth" do
    # Connect to server
    socket = UDPSocket.new
    socket.connect("demo.snmplabs.com", 161)
    socket.sync = false

    # Setup session
    session = SNMP::V3::Session.new("usr-md5-des", "authkey1", "privkey1")
    if session.must_revalidate?
      socket.write_bytes session.engine_validation_probe
      socket.flush
      session.validate socket.read_bytes(ASN1::BER)
    end

    # Make request
    ber = session.prepare(session.get("1.3.6.1.2.1.1.4.0"))
    socket.write_bytes ber
    socket.flush

    # Process response
    response = session.parse(socket.read_bytes(ASN1::BER))
    response.value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
  end

  it "should be able to query SNMPLabs with SNMPv2" do
    # Connect to server
    socket = UDPSocket.new
    socket.connect("demo.snmplabs.com", 161)
    socket.sync = false

    # Make request
    session = SNMP::Session.new
    socket.write_bytes session.get("1.3.6.1.2.1.1.4.0")
    socket.flush

    # Process response
    response = session.parse(socket.read_bytes(ASN1::BER))
    response.value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
  end
end
