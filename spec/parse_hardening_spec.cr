require "./helper"

private def context_pdu(tag : SNMP::Request, children)
  pdu = ASN1::BER.new
  pdu.tag_class = ASN1::BER::TagClass::ContextSpecific
  pdu.constructed = true
  pdu.tag_number = tag.to_u8
  pdu.children = children
  pdu
end

private def sequence(children)
  seq = ASN1::BER.new
  seq.tag_number = ASN1::BER::UniversalTags::Sequence
  seq.children = children
  seq
end

describe "SNMP parse hardening" do
  it "raises ParseError on an unknown SNMP version" do
    msg = sequence({ASN1::BER.new.set_integer(2)}) # version 2 is undefined
    expect_raises(SNMP::ParseError) { SNMP.parse(msg) }
  end

  it "raises ParseError on a truncated SNMP message (missing PDU)" do
    ver = ASN1::BER.new.set_integer(SNMP::Version::V2C.to_i)
    com = ASN1::BER.new.set_string("public", tag: ASN1::BER::UniversalTags::OctetString)
    expect_raises(SNMP::ParseError) { SNMP.parse(sequence({ver, com})) }
  end

  it "raises ParseError on a truncated PDU (missing fields)" do
    pdu = context_pdu(SNMP::Request::Get, {ASN1::BER.new.set_integer(1)}) # only request_id
    expect_raises(SNMP::ParseError) { SNMP::PDU.new(pdu) }
  end

  it "raises ParseError on an unknown PDU request tag" do
    # context tag 20 is not a valid Request
    pdu = ASN1::BER.new
    pdu.tag_class = ASN1::BER::TagClass::ContextSpecific
    pdu.constructed = true
    pdu.tag_number = 20_u32
    pdu.children = {ASN1::BER.new.set_integer(1)}
    ver = ASN1::BER.new.set_integer(SNMP::Version::V2C.to_i)
    com = ASN1::BER.new.set_string("public", tag: ASN1::BER::UniversalTags::OctetString)
    expect_raises(SNMP::ParseError) { SNMP.parse(sequence({ver, com, pdu})) }
  end

  it "raises ParseError on a v2 trap with too few varbinds" do
    vb = SNMP::VarBind.new("1.3.6.1.2.1.1.3.0")
    vb.value.set_integer(0)
    pdu = context_pdu(SNMP::Request::V2_Trap, {
      ASN1::BER.new.set_integer(0),
      ASN1::BER.new.set_integer(0),
      ASN1::BER.new.set_integer(0),
      sequence({vb.to_ber}), # only one varbind, snmpTrapOID missing
    })
    expect_raises(SNMP::ParseError) { SNMP::Trap.new(pdu) }
  end
end
