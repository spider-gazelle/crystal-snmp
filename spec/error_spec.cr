require "./helper"

describe "SNMP error model" do
  it "roots every library error under SNMP::Error" do
    SNMP::ParseError.new("x").should be_a(SNMP::Error)
    SNMP::VersionError.new("x").should be_a(SNMP::ParseError)
    SNMP::TimeoutError.new("x").should be_a(SNMP::Error)
    SNMP::Client::Error.new("x").should be_a(SNMP::Error)
    SNMP::V3::Security::Error.new("x").should be_a(SNMP::Error)
    SNMP::V3::Security::AuthenticationError.new("x").should be_a(SNMP::V3::Security::Error)
  end

  it "raises SNMP::VersionError when a V3 message reaches a V2C session" do
    # A V3 probe (version = 3) parsed by a V2C session
    bytes = "303e020103301102042841a2ed020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e02042c52f7770201000201003000"
    io = IO::Memory.new(bytes.hexbytes)
    ber = io.read_bytes(ASN1::BER)

    expect_raises(SNMP::VersionError) do
      SNMP::Session.new.parse(ber)
    end
  end

  it "raises SNMP::V3::Security::AuthenticationError on a bad signature" do
    data = "3082013802010330110204009e5d1a020300ffe3040101020103042f302d040d80001f888059dc486145a2632202010802020ab90405706970706f040c9fa0795c5587c2b88c90897204003081ee040d80001f888059dc486145a263220400a281da02042c180dbc0201000201003081cb30819506082b0601020101010004818844617277696e2069642d6573742e6c6f63616c20382e382e302044617277696e204b65726e656c2056657273696f6e20382e382e303a20467269205365702020382031373a31383a35372050445420323030363b20726f6f743a786e752d3739322e31322e362e6f626a7e312f52454c454153455f50504320506f776572204d6163696e746f7368300f06082b0601020101030043030430d3300f06082b060102010403004103029945300f06082b06010201040a004103020d8b"
    io = IO::Memory.new(data.hexbytes)
    snmp = SNMP::V3::Message.new(io.read_bytes(ASN1::BER).children)

    wrong = SNMP::V3::Security.new("pippo", "80001f888059dc486145a26322", auth_password: "wrongpwd")
    expect_raises(SNMP::V3::Security::AuthenticationError) do
      snmp.verify(wrong)
    end
  end

  it "raises ArgumentError for an unsupported SET value type" do
    expect_raises(ArgumentError) do
      SNMP::Session.new.set("1.3.6.1.2.1.1.3.0", 1.5)
    end
  end

  it "wraps a read timeout in SNMP::TimeoutError" do
    # a local UDP socket that receives but never answers → the client's read times out
    server = UDPSocket.new
    server.bind("127.0.0.1", 0)
    port = server.local_address.port

    client = SNMP::Client.new("127.0.0.1", timeout: 1, port: port)
    expect_raises(SNMP::TimeoutError) do
      client.get("1.3.6.1.2.1.1.4.0")
    end
  ensure
    server.try &.close
  end
end
