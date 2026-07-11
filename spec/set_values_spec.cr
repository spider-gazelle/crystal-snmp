require "./helper"

describe "SNMP SET value types" do
  it "encodes Counter32 as Application 1" do
    ber = SNMP::Counter32.new(0xFFFF_0001_u32).to_ber
    ber.tag_class.should eq(ASN1::BER::TagClass::Application)
    ber.tag_number.should eq(SNMP::AppTags::Counter32.to_i)
    SNMP.get_unsigned32(ber).should eq(0xFFFF_0001_u32)
  end

  it "encodes Gauge32 as Application 2" do
    ber = SNMP::Gauge32.new(42_u32).to_ber
    ber.tag_number.should eq(SNMP::AppTags::Gauge32.to_i)
    SNMP.get_unsigned32(ber).should eq(42_u32)
  end

  it "encodes TimeTicks as Application 3" do
    ber = SNMP::TimeTicks.new(100_u32).to_ber
    ber.tag_number.should eq(SNMP::AppTags::TimeTicks.to_i)
    SNMP.get_unsigned32(ber).should eq(100_u32)
  end

  it "encodes Counter64 as Application 6" do
    ber = SNMP::Counter64.new(0xFFFF_FFFF_FFFF_0001_u64).to_ber
    ber.tag_class.should eq(ASN1::BER::TagClass::Application)
    ber.tag_number.should eq(SNMP::AppTags::Counter64.to_i)
    SNMP.get_unsigned64(ber).should eq(0xFFFF_FFFF_FFFF_0001_u64)
  end

  it "encodes an IpAddress as 4 Application-0 bytes" do
    ber = SNMP::IpAddress.new("192.168.1.254").to_ber
    ber.tag_class.should eq(ASN1::BER::TagClass::Application)
    ber.tag_number.should eq(SNMP::AppTags::IPAddress.to_i)
    ber.payload.should eq(Bytes[192, 168, 1, 254])
  end

  it "encodes Opaque bytes as Application 4" do
    ber = SNMP::Opaque.new(Bytes[1, 2, 3]).to_ber
    ber.tag_number.should eq(SNMP::AppTags::Opaque.to_i)
    ber.payload.should eq(Bytes[1, 2, 3])
  end

  it "encodes an OID value" do
    ber = SNMP::OID.new("1.3.6.1.2.1.1.1.0").to_ber
    ber.get_object_id.should eq("1.3.6.1.2.1.1.1.0")
  end

  it "wires a typed value into Session#set" do
    message = SNMP::Session.new("public").set("1.3.6.1.2.1.1.3.0", SNMP::TimeTicks.new(12345_u32))
    vb = message.varbinds.first
    vb.value.tag_class.should eq(ASN1::BER::TagClass::Application)
    vb.value.tag_number.should eq(SNMP::AppTags::TimeTicks.to_i)
  end
end
