require "./helper"

describe SNMP::Client do
  it "should perform a walk" do
    client = SNMP::Client.new(TEST_SNMP_SERVER)
    client.should_not be_nil
    messages = client.walk("1.3.6.1.2.1.1.9.1.3")
    messages.should be_a(Array(SNMP::Message))
    messages.empty?.should be_false
  end

  it "should perform a walk using a block" do
    client = SNMP::Client.new(TEST_SNMP_SERVER)
    client.should_not be_nil
    messages = [] of SNMP::Message
    client.walk("1.3.6.1.2.1.1.9.1.3") do |message|
      messages << message
    end
    messages.empty?.should be_false
  end
end
