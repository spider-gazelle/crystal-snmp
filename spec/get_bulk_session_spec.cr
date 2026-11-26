require "./helper"

describe SNMP::Session do
  it "round-trips GetBulk counts beyond the error-status enum" do
    session = SNMP::Session.new("public")
    message = session.get_bulk(["1.3.6.1.2.1.2.2"], non_repeaters: 20, max_repetitions: 25)
    parsed = session.parse(message.to_ber)
    parsed.request.should eq(SNMP::Request::GetBulk)
    parsed.non_repeaters.should eq(20)
    parsed.max_repetitions.should eq(25)
    parsed.error_status.should eq(SNMP::ErrorStatus::NoError)
    parsed.error_index.should eq(0)
  end
end

describe SNMP::V3::Session do
  it "round-trips GetBulk counts in the scoped PDU" do
    session = SNMP::V3::Session.new("user")
    message = session.get_bulk(["1.3.6.1.2.1.2.2"], non_repeaters: 1, max_repetitions: 15)
    parsed = session.parse(session.prepare(message))
    parsed.request.should eq(SNMP::Request::GetBulk)
    parsed.non_repeaters.should eq(1)
    parsed.max_repetitions.should eq(15)
  end
end
