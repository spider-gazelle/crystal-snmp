require "./helper"

describe SNMP::Session do
  it "builds a GetBulk message with non-repeaters / max-repetitions" do
    message = SNMP::Session.new("public").get_bulk(["1.3.6.1.2.1.2.2"], non_repeaters: 0, max_repetitions: 25)
    message.request.should eq(SNMP::Request::GetBulk)
    message.non_repeaters.should eq(0)
    message.max_repetitions.should eq(25)

    ber = message.to_ber
    pdu = ber.children[2]
    pdu.children[2].get_integer.should eq(25) # max-repetitions slot
  end
end

describe SNMP::V3::Session do
  it "builds a GetBulk message with non-repeaters / max-repetitions" do
    message = SNMP::V3::Session.new("user").get_bulk(["1.3.6.1.2.1.2.2"], max_repetitions: 15)
    message.request.should eq(SNMP::Request::GetBulk)
    message.pdu.as(SNMP::PDU).max_repetitions.should eq(15)
  end
end
