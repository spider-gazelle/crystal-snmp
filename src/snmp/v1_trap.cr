# An RFC 1157 Trap-PDU. It is its own variant of the protocol's PDU CHOICE —
# not an SNMPv2 trap — so it derives from PDU directly and carries the v1
# fields (enterprise, agent address, generic/specific trap, timestamp) itself.
# The v2-style request-id / error fields inherited from PDU have no meaning in
# a v1 trap and stay at their defaults.
class SNMP::V1Trap < SNMP::PDU
  def initialize(ber : ASN1::BER)
    pdu = SNMP.ber_fields(ber, 6, "v1 trap")
    @enterprise = pdu[0].get_object_id
    @agent_address = pdu[1].payload.join(".")
    @generic_trap = SNMP.decode_enum(GenericTrap, pdu[2].get_integer, "generic-trap")
    @specific_trap = pdu[3].get_integer.to_i32
    @time_ticks = SNMP.get_unsigned32(pdu[4])
    @varbinds = pdu[5].children.map do |varbind|
      VarBind.new(varbind)
    end

    # The v2-style PDU fields do not exist on the v1 wire
    @request_id = 0
    @error_status = ErrorStatus::NoError
    @error_index = 0
  end

  property enterprise : String
  property agent_address : String
  property generic_trap : GenericTrap
  property specific_trap : Int32
  property time_ticks : UInt32

  def initialize(@agent_address, @generic_trap, @specific_trap = 0, @enterprise = "", @time_ticks = 0_u32, varbinds : Array(VarBind) = [] of VarBind, request_id = 0)
    super(request_id, varbinds)
  end

  # RFC 1157 Trap-PDU wire structure — distinct from the standard PDU layout, so
  # this overrides `PDU#to_ber`.
  def to_ber(tag_number)
    enterprise = ASN1::BER.new.set_object_id(@enterprise)
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
