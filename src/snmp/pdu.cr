class SNMP
  class PDU
    def initialize(ber : ASN1::BER)
      pdu = ber.children
      @request_id = pdu[0].get_integer.to_i32
      @error_status = ErrorStatus.from_value(pdu[1].get_integer)
      @error_index = pdu[2].get_integer.to_i32
      @raw_varbinds = pdu[3].children
      @varbinds = @raw_varbinds.map do |varbind|
        VarBind.new(varbind)
      end
    end

    def initialize(@request_id, @error_status, @error_index)
      @raw_varbinds = [] of ASN1::BER
      @varbinds = [] of VarBind
    end

    property request_id : Int32
    property error_status : ErrorStatus
    property error_index : Int32
    property varbinds : Array(VarBind)
    @raw_varbinds : Array(ASN1::BER)
  end
end
