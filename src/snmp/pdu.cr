class SNMP
  class PDU
    enum ErrorStatus
      NoError
      TooBig
      NoSuchName
      BadValue
      ReadOnly
      GenErr
    end

    def initialize(pdu : Array(ASN1::BER))
      @request_id = pdu[0].get_integer.to_i32
      @error_status = ErrorStatus.from_value(pdu[1].get_integer)
      @error_index = pdu[2].get_integer.to_i32
      @varbinds = pdu[3].children
    end

    property request_id : Int32
    property error_status : ErrorStatus
    property error_index : Int32
    property varbinds : Array(ASN1::BER)
  end

  class TrapPDU
    def initialize(pdu : Array(ASN1::BER))
      @oid = pdu[0].get_object_id
      @agent_address = pdu[1].payload.join(".")
      @generic_trap = GenericTrap.from_value(pdu[2].get_integer)
      @specific_trap = pdu[3].get_integer.to_i32
      # timestamp = pdu[4] # TimeTicks
      @varbinds = pdu[5].children
    end

    property oid : String
    property agent_address : String
    property generic_trap : GenericTrap
    property specific_trap : Int32
    property varbinds : Array(ASN1::BER)
  end
end
