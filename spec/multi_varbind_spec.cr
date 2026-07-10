require "./helper"

describe SNMP::Session do
  oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]

  it "builds a multi-varbind Get from several OIDs" do
    message = SNMP::Session.new("public").get(oids)
    message.request.should eq(SNMP::Request::Get)
    message.varbinds.map(&.oid).should eq(oids)
  end

  it "builds a multi-varbind GetNext from several OIDs" do
    message = SNMP::Session.new("public").get_next(oids)
    message.request.should eq(SNMP::Request::GetNext)
    message.varbinds.map(&.oid).should eq(oids)
  end

  it "round-trips a multi-varbind Get through BER" do
    message = SNMP::Session.new("public").get(oids)
    parsed = SNMP::Message.new(message.to_ber.children)
    parsed.varbinds.map(&.oid).should eq(oids)
  end

  it "still accepts a single OID (single-varbind Get)" do
    message = SNMP::Session.new("public").get("1.3.6.1.2.1.1.1.0")
    message.varbinds.map(&.oid).should eq(["1.3.6.1.2.1.1.1.0"])
  end
end

describe SNMP::V3::Session do
  oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"]

  it "builds a multi-varbind Get from several OIDs" do
    message = SNMP::V3::Session.new("user").get(oids)
    message.request.should eq(SNMP::Request::Get)
    message.pdu.varbinds.map(&.oid).should eq(oids)
  end

  it "builds a multi-varbind GetNext from several OIDs" do
    message = SNMP::V3::Session.new("user").get_next(oids)
    message.request.should eq(SNMP::Request::GetNext)
    message.pdu.varbinds.map(&.oid).should eq(oids)
  end
end
