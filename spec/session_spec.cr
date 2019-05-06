require "./helper"

describe SNMP::V3::Session do
  it "should know when to revalidate" do
    session = SNMP::V3::Session.new("username")
    session.must_revalidate?.should eq(true)
    session.engine_id.should eq("")

    message = session.engine_validation_probe
    message.engine_id = "000000000000000000000002"
    message.security_params.engine_time = 36
    message.security_params.engine_boots = 1

    session.validate(message)

    session.engine_id.should eq("000000000000000000000002")
    session.must_revalidate?.should eq(false)
  end
end
