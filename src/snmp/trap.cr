class SNMP
  # https://tools.ietf.org/search/rfc3416#section-4.2.6
  class Trap < PDU
    def initialize(ber : ASN1::BER)
      super(ber)

      @time_ticks = SNMP.get_unsigned32(@varbinds[0].value)
      @oid = @varbinds[1].value.get_object_id
    end

    property time_ticks : UInt32
    property oid : String
  end
end
