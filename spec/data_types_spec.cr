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
end
