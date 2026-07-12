require "./helper"

describe SNMP::PDU do
  it "#value returns the value BER and #varbind the first varbind" do
    vb = SNMP::VarBind.new("1.3.6.1.2.1.1.1.0")
    vb.value.set_string("hi")
    pdu = SNMP::PDU.new(varbinds: [vb])

    pdu.varbind.should be(vb)
    pdu.value.should be(vb.value)
    pdu.value.get_string.should eq("hi")
  end
end

describe SNMP::Message do
  it "#value returns the value BER and #varbind the first varbind" do
    message = SNMP::Session.new("public").get("1.3.6.1.2.1.1.1.0")

    message.varbind.oid.should eq("1.3.6.1.2.1.1.1.0")
    message.value.should be(message.varbind.value)
  end
end
