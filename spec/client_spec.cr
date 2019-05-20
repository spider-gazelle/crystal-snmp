require "./helper"

describe SNMP::Client do
  it "should perform a walk" do
    client = SNMP::Client.new("demo.snmplabs.com")
    client.should_not be_nil
    messages = client.walk("1.3.6.1.2.1.1.9.1.3")
    messages.should be_a(Array(SNMP::Message))
    messages.empty?.should be_false
    messages.size.should eq 8
  end
end
