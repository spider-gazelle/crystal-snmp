require "./helper"

describe SNMP::Client do
  describe ".oid_within?" do
    it "matches the base itself and its true children" do
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.1", "1.3.6.1.2.1.2.2.1.1").should be_true
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.1").should be_true
    end

    it "rejects a sibling column that merely shares a string prefix" do
      # column 10 (ifInOctets) is NOT a child of column 1 (ifIndex)
      SNMP::Client.oid_within?("1.3.6.1.2.1.2.2.1.10.5", "1.3.6.1.2.1.2.2.1.1").should be_false
    end
  end

  it "should perform a walk", tags: "e2e" do
    client = SNMP::Client.new(TEST_SNMP_SERVER)
    client.should_not be_nil
    messages = client.walk("1.3.6.1.2.1.1.9.1.3")
    messages.should be_a(Array(SNMP::Message))
    messages.empty?.should be_false
  end

  it "should perform a walk using a block", tags: "e2e" do
    client = SNMP::Client.new(TEST_SNMP_SERVER)
    client.should_not be_nil
    messages = [] of SNMP::Message
    client.walk("1.3.6.1.2.1.1.9.1.3") do |message|
      messages << message
    end
    messages.empty?.should be_false
  end
end
