require "./helper"

describe SNMP::V1Trap do
  it "is a PDU but not a v2 Trap (RFC 1157 traps are their own PDU variant)" do
    trap = SNMP::V1Trap.new("10.0.0.1", SNMP::GenericTrap::LinkDown, 0, enterprise: "1.3.6.1.4.1.9")
    trap.is_a?(SNMP::PDU).should be_true
    trap.is_a?(SNMP::Trap).should be_false
  end

  it "exposes the enterprise OID as #enterprise, keeping PDU#oid for the first varbind" do
    vb = SNMP::VarBind.new("1.3.6.1.2.1.2.2.1.1.26")
    vb.value.set_integer(26)
    trap = SNMP::V1Trap.new("10.0.0.1", SNMP::GenericTrap::LinkUp, 0,
      enterprise: "1.3.6.1.4.1.9", time_ticks: 42_u32, varbinds: [vb])

    trap.enterprise.should eq("1.3.6.1.4.1.9")
    trap.oid.should eq("1.3.6.1.2.1.2.2.1.1.26")
    trap.time_ticks.should eq(42)
  end
end
