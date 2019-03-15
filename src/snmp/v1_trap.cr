class SNMP
  class TrapPDU
    def initialize(ber : ASN1::BER)
      pdu = ber.children
      @oid = pdu[0].get_object_id
      @agent_address = pdu[1].payload.join(".")
      @generic_trap = GenericTrap.from_value(pdu[2].get_integer)
      @specific_trap = pdu[3].get_integer.to_i32
      # timestamp = pdu[4] # TimeTicks
      @raw_varbinds = pdu[5].children
      @varbinds = @raw_varbinds.map do |varbind|
        VarBind.new(varbind)
      end
    end

    property oid : String
    property agent_address : String
    property generic_trap : GenericTrap
    property specific_trap : Int32
    property varbinds : Array(VarBind)
    @raw_varbinds : Array(ASN1::BER)
  end
end
