require "./helper"

describe SNMP do
  it "should parse a SNMP V1 Trap" do
    b = Bytes[48, 129, 139, 2, 1, 0, 4, 11, 53, 114, 78, 84, 103, 33, 112, 109, 49, 99, 107, 164, 121, 6, 8, 43, 6, 1, 6, 3, 1, 1, 5, 64, 4, 10, 230, 254, 28, 2, 1, 3, 2, 1, 0, 67, 4, 14, 162, 200, 72, 48, 91, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 1, 26, 2, 1, 26, 48, 35, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 2, 26, 4, 21, 71, 105, 103, 97, 98, 105, 116, 69, 116, 104, 101, 114, 110, 101, 116, 49, 47, 48, 47, 49, 57, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 3, 26, 2, 1, 6, 48, 18, 6, 12, 43, 6, 1, 4, 1, 9, 2, 2, 1, 1, 20, 26, 4, 2, 117, 112]
    io = IO::Memory.new(b)

    snmp = SNMP.new(io.read_bytes(ASN1::BER))
    snmp.version.should eq(SNMP::Version::V1)
    snmp.request.should eq(SNMP::Request::V1_Trap)
    snmp.community.should eq("5rNTg!pm1ck")

    snmp.varbinds.map(&.oid).should eq(["1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.2.26", "1.3.6.1.2.1.2.2.1.3.26", "1.3.6.1.4.1.9.2.2.1.1.20.26"])
    snmp.expects_response?.should eq(false)
    snmp.trap?.should eq(true)

    snmp_pdu = snmp.pdu
    if snmp_pdu.is_a?(SNMP::V1Trap)
      snmp_pdu.oid.should eq("1.3.6.1.6.3.1.1.5")
      snmp_pdu.agent_address.should eq("10.230.254.28")
      snmp_pdu.generic_trap.should eq(SNMP::GenericTrap::LinkUp)
      snmp_pdu.specific_trap.should eq(0)
      snmp_pdu.time_ticks.should eq(245549128)

      snmp_pdu.varbinds.map(&.oid).should eq(["1.3.6.1.2.1.2.2.1.1.26", "1.3.6.1.2.1.2.2.1.2.26", "1.3.6.1.2.1.2.2.1.3.26", "1.3.6.1.4.1.9.2.2.1.1.20.26"])
    else
      raise "should be a v1 trap pdu"
    end
  end

  it "should be able to write a SNMP V1 responses" do
    b = Bytes[0x30, 0x38, 0x02, 0x01, 0x00, 0x04, 0x06,
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2, 0x2b, 0x02, 0x01, 0x26, 0x02,
      0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b,
      0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12, 0x2b, 0x06, 0x01,
      0x04, 0x01, 0x8f, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5d, 0x01, 0x1b,
      0x02, 0x02, 0x01]
    io = IO::Memory.new(b)

    snmp = SNMP.new(io.read_bytes(ASN1::BER))
    snmp.version.should eq(SNMP::Version::V1)
    snmp.community.should eq("public")

    io2 = IO::Memory.new
    io2.write_bytes snmp

    io2.to_slice.should eq(b)
  end
end
