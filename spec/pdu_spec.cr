require "./helper"

describe SNMP::PDU do
  it "decodes error-status as the RFC-3416 enum and error-index as a position" do
    varbinds = ASN1::BER.new
    varbinds.tag_number = ASN1::BER::UniversalTags::Sequence
    varbinds.children = [] of ASN1::BER

    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::ContextSpecific
    ber.constructed = true
    ber.tag_number = SNMP::Request::Response.to_u8
    ber.children = {
      ASN1::BER.new.set_integer(1), # request-id
      ASN1::BER.new.set_integer(3), # error-status = badValue(3)
      ASN1::BER.new.set_integer(1), # error-index  = 1 (first varbind)
      varbinds,
    }

    pdu = SNMP::PDU.new(ber)
    pdu.error_status.should eq(SNMP::ErrorStatus::BadValue)
    pdu.error_index.should eq(1)
  end
end
