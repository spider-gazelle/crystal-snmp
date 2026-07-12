class SNMP::V1Trap < SNMP::Trap
  def initialize(ber : ASN1::BER)
    pdu = SNMP.ber_fields(ber, 6, "v1 trap")
    @oid = pdu[0].get_object_id
    @agent_address = pdu[1].payload.join(".")
    @generic_trap = SNMP.decode_enum(GenericTrap, pdu[2].get_integer, "generic-trap")
    @specific_trap = pdu[3].get_integer.to_i32
    @time_ticks = SNMP.get_unsigned32(pdu[4])
    @varbinds = pdu[5].children.map do |varbind|
      VarBind.new(varbind)
    end

    # Compatibility with regular PDUs
    # V1 traps are very different: https://tools.ietf.org/html/rfc1157#page-27
    @request_id = 0
    @error_status = ErrorStatus::NoError
    @error_index = 0
  end

  property agent_address : String
  property generic_trap : GenericTrap
  property specific_trap : Int32

  def initialize(@agent_address, @generic_trap, @specific_trap, **args)
    super(**args)
  end

  # RFC 1157 Trap-PDU wire structure — distinct from the standard PDU layout, so
  # this overrides `PDU#to_ber`. `@oid` holds the enterprise OID.
  def to_ber(tag_number)
    enterprise = ASN1::BER.new.set_object_id(@oid)
    agent = IpAddress.new(@agent_address).to_ber
    generic = ASN1::BER.new.set_integer(@generic_trap.to_i)
    specific = ASN1::BER.new.set_integer(@specific_trap)
    timestamp = TimeTicks.new(@time_ticks).to_ber

    varb = ASN1::BER.new
    varb.tag_number = ASN1::BER::UniversalTags::Sequence
    varb.children = varbinds.map &.to_ber

    pdu = ASN1::BER.new
    pdu.tag_class = ASN1::BER::TagClass::ContextSpecific
    pdu.constructed = true
    pdu.tag_number = tag_number
    pdu.children = {enterprise, agent, generic, specific, timestamp, varb}
    pdu
  end
end
