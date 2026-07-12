require "./helper"

private def ifx(col, &)
  vb = SNMP::VarBind.new("1.3.6.1.2.1.31.1.1.1.#{col}.7")
  yield vb
  vb
end

describe SNMP::Helpers::IfEntry do
  it "parses ifXTable high-capacity counters and identity fields" do
    big_in = 0x1_0000_0000_5_u64 # > 2^32, would wrap a 32-bit counter

    vbs = [
      ifx(1, &.value.set_string("eth7")),
      ifx(6, &.set_unsigned64(big_in)),
      ifx(10, &.set_unsigned64(999_u64)),
      ifx(14, &.value.set_integer(1)), # enabled
      ifx(15, &.set_unsigned32(10_000_u32)),
      ifx(16, &.value.set_integer(1)), # promiscuous true
      ifx(17, &.value.set_integer(2)), # connector absent
      ifx(18, &.value.set_string("uplink-to-core")),
      ifx(19, &.set_unsigned32(4242_u32)),
    ]

    e = SNMP::Helpers::IfEntry.new(SNMP::PDU.new(varbinds: vbs))
    e.name.should eq("eth7")
    e.hc_in_octets.should eq(big_in)
    e.hc_out_octets.should eq(999_u64)
    e.link_up_down_trap_enabled?.should be_true
    e.high_speed.should eq(10_000_u32)
    e.promiscuous_mode?.should be_true
    e.connector_present?.should be_false
    e.alias_name.should eq("uplink-to-core")
    e.counter_discontinuity_time.should eq(4242_u32)
  end

  it "still parses the classic ifTable columns after the refactor" do
    vbs = [
      SNMP::VarBind.new("1.3.6.1.2.1.2.2.1.1.7").tap(&.value.set_integer(7)),
      SNMP::VarBind.new("1.3.6.1.2.1.2.2.1.2.7").tap(&.value.set_string("Gi0/7")),
    ]
    e = SNMP::Helpers::IfEntry.new(SNMP::PDU.new(varbinds: vbs))
    e.index.should eq(7)
    e.descr.should eq("Gi0/7")
  end
end
