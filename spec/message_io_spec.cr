require "./helper"

describe SNMP::Message do
  it "round-trips through IO#write_bytes / IO#read_bytes" do
    msg = SNMP::Session.new.get("1.3.6.1.2.1.1.4.0")

    io = IO::Memory.new
    io.write_bytes(msg)
    io.rewind
    parsed = io.read_bytes(SNMP::Message)

    parsed.community.should eq("public")
    parsed.oid.should eq("1.3.6.1.2.1.1.4.0")
  end
end

describe SNMP::V3::Message do
  it "parses from a single BER" do
    bytes = "303e020103301102042841a2ed020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e02042c52f7770201000201003000"
    ber = IO::Memory.new(bytes.hexbytes).read_bytes(ASN1::BER)

    msg = SNMP::V3::Message.new(ber)
    msg.version.should eq(SNMP::Version::V3)
  end
end
