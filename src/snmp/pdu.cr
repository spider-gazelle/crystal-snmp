class SNMP
  class PDU
    def initialize(pdu : Array(ASN1::BER))
      @request_id = pdu[0].get_integer.to_i32
      @error_status = ErrorStatus.from_value(pdu[1].get_integer)
      @error_index = pdu[2].get_integer.to_i32
      @varbinds = pdu[3].children
    end

    def initialize(@request_id, @error_status, @error_index)
      @varbinds = [] of ASN1::BER
    end

    property request_id : Int32
    property error_status : ErrorStatus
    property error_index : Int32
    @varbinds : Array(ASN1::BER)
    @lazy_varbinds : Array(VarBind)?

    def varbinds
      if vb = @lazy_varbinds
        vb
      else
        @lazy_varbinds = vb = @varbinds.map do |varbind|
          VarBind.new(varbind.children)
        end
        vb
      end
    end
  end
end
