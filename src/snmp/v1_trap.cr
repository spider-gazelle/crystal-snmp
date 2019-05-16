class SNMP::V1Trap < SNMP::Trap
  def initialize(ber : ASN1::BER)
    pdu = ber.children
    @oid = pdu[0].get_object_id
    @agent_address = pdu[1].payload.join(".")
    @generic_trap = GenericTrap.from_value(pdu[2].get_integer)
    @specific_trap = pdu[3].get_integer.to_i32
    @time_ticks = SNMP.get_unsigned32(pdu[4])
    @varbinds = pdu[5].children.map do |varbind|
      VarBind.new(varbind)
    end

    # Compatibility with regular PDUs
    # V1 traps are very different: https://tools.ietf.org/html/rfc1157#page-27
    @request_id = 0
    @error_status = ErrorStatus::NoError
    @error_index = ErrorIndex::NoError
  end

  property agent_address : String
  property generic_trap : GenericTrap
  property specific_trap : Int32

  def initialize(@agent_address, @generic_trap, @specific_trap, **args)
    super(**args)
  end
end
