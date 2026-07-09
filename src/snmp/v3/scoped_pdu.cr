# This is not really a PDU, but a container for a PDU
class SNMP::V3::ScopedPDU
  def initialize(ber : ASN1::BER)
    pdu = SNMP.ber_fields(ber, 3, "scoped PDU")
    @context_engine_id = pdu[0].get_hexstring
    # contextName is an OCTET STRING (RFC 3412), not an OID
    @context = pdu[1].get_string
    @request = SNMP.decode_enum(Request, pdu[2].tag_number, "PDU request type")

    case @request
    when Request::V1_Trap
      @pdu = V1Trap.new(pdu[2])
    when Request::V2_Trap
      @pdu = Trap.new(pdu[2])
    else
      @pdu = PDU.new(pdu[2])
    end
  end

  def initialize(@request, @pdu, @context_engine_id = "", @context = "")
  end

  property context_engine_id : String
  property request : Request
  property context : String
  property pdu : PDU | Trap

  def to_ber
    engine = ASN1::BER.new.set_hexstring(@context_engine_id)
    context = ASN1::BER.new.set_string(@context, tag: UniversalTags::OctetString)

    pdu = @pdu.to_ber(@request.to_u8)

    snmp = ASN1::BER.new
    snmp.tag_number = UniversalTags::Sequence
    snmp.children = {engine, context, pdu}
    snmp
  end
end
