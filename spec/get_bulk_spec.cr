require "./helper"

describe SNMP::PDU do
  it "encodes non-repeaters and max-repetitions in a GetBulk PDU" do
    pdu = SNMP::PDU.new(request_id: 42, varbinds: [SNMP::VarBind.new("1.3.6.1.2.1.2.2")])
    pdu.non_repeaters = 1
    pdu.max_repetitions = 10

    ber = pdu.to_ber(SNMP::Request::GetBulk.to_u8)
    # GetBulk reuses the error-status / error-index slots as non-repeaters / max-repetitions.
    ber.children[1].get_integer.should eq(1)
    ber.children[2].get_integer.should eq(10)
  end

  it "keeps error-status / error-index in a non-bulk PDU" do
    pdu = SNMP::PDU.new(request_id: 42, varbinds: [SNMP::VarBind.new("1.3.6.1.2.1.1.1.0")])
    pdu.error_status = SNMP::ErrorStatus::TooBig
    pdu.error_index = 3

    ber = pdu.to_ber(SNMP::Request::Get.to_u8)
    ber.children[1].get_integer.should eq(SNMP::ErrorStatus::TooBig.to_i)
    ber.children[2].get_integer.should eq(3)
  end
end
