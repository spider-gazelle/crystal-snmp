require "./helper"

describe SNMP::Session do
  it "builds a multi-varbind Set from a Hash (insertion order preserved)" do
    values = {
      "1.3.6.1.2.1.1.5.0" => "new-sysname",
      "1.3.6.1.2.1.1.3.0" => SNMP::TimeTicks.new(9_u32),
    }
    message = SNMP::Session.new("public").set(values)

    message.request.should eq(SNMP::Request::Set)
    message.varbinds.map(&.oid).should eq(values.keys.to_a)
    message.varbinds[0].value.get_string.should eq("new-sysname")
    message.varbinds[1].value.tag_number.should eq(SNMP::AppTags::TimeTicks.to_i)
  end
end

describe SNMP::V3::Session do
  it "builds a multi-varbind Set from a Hash" do
    values = {
      "1.3.6.1.2.1.1.5.0" => "name",
      "1.3.6.1.2.1.1.6.0" => "location",
    }
    message = SNMP::V3::Session.new("user").set(values)

    message.request.should eq(SNMP::Request::Set)
    message.pdu.varbinds.map(&.oid).should eq(values.keys.to_a)
  end
end
