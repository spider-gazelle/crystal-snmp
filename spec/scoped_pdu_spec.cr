require "./helper"

describe SNMP::V3::ScopedPDU do
  it "round-trips a non-empty contextName as an OCTET STRING" do
    pdu = SNMP::PDU.new(request_id: 1)
    scoped = SNMP::V3::ScopedPDU.new(SNMP::Request::Get, pdu, context_engine_id: "80000000010203", context: "vlan-10")

    reparsed = SNMP::V3::ScopedPDU.new(scoped.to_ber)
    reparsed.context.should eq("vlan-10")
    reparsed.context_engine_id.should eq("80000000010203")
  end

  it "keeps an empty contextName empty" do
    pdu = SNMP::PDU.new(request_id: 1)
    scoped = SNMP::V3::ScopedPDU.new(SNMP::Request::Get, pdu, context_engine_id: "80000000010203")

    reparsed = SNMP::V3::ScopedPDU.new(scoped.to_ber)
    reparsed.context.should eq("")
  end
end
