# This is not really a PDU, but a container for a PDU
class SNMP::V3::ScopedPDU
  def initialize(ber : ASN1::BER)
    pdu = ber.children
    @engine_id = pdu[0].get_string
    @context = if pdu[1].get_bytes.empty?
                 ""
               else
                 pdu[1].get_object_id
               end
    @request = Request.from_value(pdu[2].tag_number)

    case @request
    when Request::V1_Trap
      @pdu = V1Trap.new(pdu[2])
    when Request::V2_Trap
      @pdu = Trap.new(pdu[2])
    else
      @pdu = PDU.new(pdu[2])
    end
  end

  def initialize(@request, @engine_id = "", @context = "", **args)
    case @request
    when Request::V1_Trap
      @pdu = V1Trap.new(**args)
    when Request::V2_Trap
      @pdu = Trap.new(**args)
    else
      @pdu = PDU.new(**args)
    end
  end

  property engine_id : String
  property request : Request
  property context : String
  property pdu : PDU | Trap

  def to_ber
    engine = ASN1::BER.new.set_string(@engine_id, ASN1::BER::UniversalTags::OctetString)
    oid = if @context.empty?
            ASN1::BER.new.set_string("", tag: UniversalTags::OctetString)
          else
            ASN1::BER.new.set_object_id(@context)
          end

    pdu = @pdu.to_ber(@request.to_u8)

    snmp = ASN1::BER.new
    snmp.tag_number = ASN1::BER::UniversalTags::Sequence
    snmp.children = {engine, oid, pdu}
    snmp
  end
end