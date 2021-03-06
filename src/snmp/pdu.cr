class SNMP::PDU
  def initialize(ber : ASN1::BER)
    pdu = ber.children
    @request_id = pdu[0].get_integer.to_i32
    @error_status = ErrorStatus.from_value(pdu[1].get_integer)
    @error_index = ErrorIndex.from_value(pdu[2].get_integer) # pdu[2].get_integer.to_i32
    @varbinds = pdu[3].children.map do |varbind|
      VarBind.new(varbind)
    end
  end

  def initialize(@request_id = rand(2147483647), @varbinds : Array(VarBind) = [] of VarBind, @error_status = ErrorStatus::NoError, @error_index = ErrorIndex::NoError)
  end

  def initialize(@request_id = rand(2147483647), varbind : VarBind? = nil, @error_status = ErrorStatus::NoError, @error_index = ErrorIndex::NoError)
    if varbind
      @varbinds = [varbind]
    else
      @varbinds = [] of VarBind
    end
  end

  property request_id : Int32
  property error_status : ErrorStatus
  property error_index : ErrorIndex
  property varbinds : Array(VarBind)

  def new_request_id
    @request_id = rand(2147483647)
  end

  # shortcut for `.varbinds[0].oid`
  def oid
    @varbinds[0].oid
  end

  # shortcut for `.varbinds[0].value`
  def value
    @varbinds[0]
  end

  def to_ber(tag_number)
    req = ASN1::BER.new
    req.set_integer(@request_id)

    error = ASN1::BER.new
    error.set_integer(@error_status.to_i)

    index = ASN1::BER.new
    index.set_integer(@error_index.to_i)

    varb = ASN1::BER.new
    varb.tag_number = ASN1::BER::UniversalTags::Sequence
    varb.children = varbinds.map &.to_ber

    pdu = ASN1::BER.new
    pdu.tag_class = ASN1::BER::TagClass::ContextSpecific
    pdu.constructed = true
    pdu.tag_number = tag_number
    pdu.children = {req, error, index, varb}
    pdu
  end
end
