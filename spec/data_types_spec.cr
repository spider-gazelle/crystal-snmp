require "./helper"

describe SNMP do
  describe ".get_unsigned64" do
    it "decodes a 9-byte Counter64 with the high bit set (leading 0x00 pad)" do
      ber = ASN1::BER.new
      ber.tag_number = ASN1::BER::UniversalTags::OctetString
      ber.payload = Bytes[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
      SNMP.get_unsigned64(ber).should eq(UInt64::MAX)
    end
  end

  describe ".get_unsigned32" do
    it "decodes a 5-byte Counter32/Gauge32 with the high bit set (leading 0x00 pad)" do
      ber = ASN1::BER.new
      ber.tag_number = ASN1::BER::UniversalTags::OctetString
      ber.payload = Bytes[0x00, 0xFF, 0xFF, 0xFF, 0xFF]
      SNMP.get_unsigned32(ber).should eq(UInt32::MAX)
    end
  end

  describe ".set_unsigned64" do
    it "pads to 8 bytes by default and round-trips" do
      ber = SNMP.set_unsigned64(0x0102_u64)
      ber.payload.size.should eq(8)
      SNMP.get_unsigned64(ber).should eq(0x0102_u64)
    end

    it "strips leading zero bytes with padding: false" do
      ber = SNMP.set_unsigned64(0x0102_u64, padding: false)
      ber.payload.should eq(Bytes[0x01, 0x02])
      SNMP.get_unsigned64(ber).should eq(0x0102_u64)
    end
  end

  describe ".set_unsigned32" do
    it "strips leading zero bytes with padding: false" do
      ber = SNMP.set_unsigned32(0x7F_u32, padding: false)
      ber.payload.should eq(Bytes[0x7F])
      SNMP.get_unsigned32(ber).should eq(0x7F_u32)
    end
  end
end
