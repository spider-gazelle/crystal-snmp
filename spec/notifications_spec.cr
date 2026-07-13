require "./helper"

# Serialize a message to the wire and read it back, exercising encode + decode.
private def round_trip(message : SNMP::Message) : SNMP::Message
  io = IO::Memory.new
  io.write_bytes message.to_ber
  io.rewind
  SNMP.parse(io.read_bytes(ASN1::BER))
end

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TRAP_OID   = "1.3.6.1.6.3.1.1.4.1.0"

describe SNMP::Session do
  it "builds an SNMPv2-Trap with sysUpTime + snmpTrapOID prepended" do
    payload = SNMP::VarBind.new("1.3.6.1.2.1.1.1.0")
    payload.value.set_string("boom")

    msg = SNMP::Session.new("public").trap_v2("1.3.6.1.4.1.8072.2.3.0.1", uptime: 12_345, varbinds: [payload])
    parsed = round_trip(msg)

    parsed.request.should eq(SNMP::Request::V2_Trap)
    parsed.varbinds[0].oid.should eq(SYS_UPTIME)
    SNMP.get_unsigned32(parsed.varbinds[0].value).should eq(12_345)
    parsed.varbinds[1].oid.should eq(TRAP_OID)
    parsed.varbinds[1].value.get_object_id.should eq("1.3.6.1.4.1.8072.2.3.0.1")
    parsed.varbinds[2].oid.should eq("1.3.6.1.2.1.1.1.0")
    parsed.varbinds[2].value.get_string.should eq("boom")
  end

  it "builds an Inform (same shape, Inform request)" do
    msg = SNMP::Session.new("public").inform("1.3.6.1.4.1.8072.2.3.0.1", uptime: 7)
    parsed = round_trip(msg)

    parsed.request.should eq(SNMP::Request::Inform)
    parsed.varbinds[0].oid.should eq(SYS_UPTIME)
    parsed.varbinds[1].value.get_object_id.should eq("1.3.6.1.4.1.8072.2.3.0.1")
  end

  it "builds an SNMPv1 Trap with its own wire structure" do
    msg = SNMP::Session.new("public").trap_v1(
      "1.3.6.1.4.1.9", "10.0.0.1", SNMP::GenericTrap::LinkDown, 0, uptime: 999)
    parsed = round_trip(msg)

    parsed.version.should eq(SNMP::Version::V1)
    parsed.request.should eq(SNMP::Request::V1_Trap)
    trap = parsed.pdu.as(SNMP::V1Trap)
    trap.enterprise.should eq("1.3.6.1.4.1.9")
    trap.agent_address.should eq("10.0.0.1")
    trap.generic_trap.should eq(SNMP::GenericTrap::LinkDown)
    trap.specific_trap.should eq(0)
    trap.time_ticks.should eq(999)
  end
end
