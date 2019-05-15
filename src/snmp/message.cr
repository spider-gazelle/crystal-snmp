require "./pdu"
require "./trap"
require "./v1_trap"
require "./varbind"
require "./data_types"

class SNMP::Message
  def initialize(snmp : Array(ASN1::BER))
    @version = Version.from_value(snmp[0].get_integer)
    @community = snmp[1].get_string
    @request = Request.from_value(snmp[2].tag_number)

    case @request
    when Request::V1_Trap
      @pdu = V1Trap.new(snmp[2])
    when Request::V2_Trap
      @pdu = Trap.new(snmp[2])
    else
      @pdu = PDU.new(snmp[2])
    end
  end

  def initialize(@community, @request, varbind : VarBind? | Array(VarBind) = nil, request_id = rand(2147483647), error_status = ErrorStatus::NoError, error_index = 0, @version = Version::V2C)
    @pdu = PDU.new(request_id, varbind, error_status, error_index)
  end

  getter pdu : PDU | Trap | V1Trap
  property version : Version
  property request : Request
  property community : String

  {% for proxy in [:varbinds, :request_id, :error_index, :error_status] %}
    def {{proxy.id}}
      @pdu.{{proxy.id}}
    end

    def {{proxy.id}}=(value)
      @pdu.{{proxy.id}} = value
    end
  {% end %}

  # Returns true if the current packet is a trap / inform
  def trap?
    {Request::V1_Trap, Request::V2_Trap, Request::Inform}.includes? @request
  end

  # Returns true if the current SNMP packet is expecting a response
  def expects_response?
    {Request::Get, Request::GetNext, Request::Set, Request::GetBulk, Request::Inform}.includes? @request
  end

  # shortcut for `.varbinds[0].oid`
  def oid
    @pdu.oid
  end

  # shortcut for `.varbinds[0].value`
  def value
    @pdu.value
  end

  # Builds a response object based on the current request
  def build_reply
    self.class.new(@community, Request::Response, request_id: @pdu.request_id, version: @version)
  end

  def new_request_id
    @pdu.new_request_id
  end

  def to_ber(pdu = @pdu.to_ber(@request.to_u8))
    ver = ASN1::BER.new.set_integer(@version.to_i)
    com = ASN1::BER.new.set_string(@community, ASN1::BER::UniversalTags::OctetString)

    # write SNMP sequence
    snmp = ASN1::BER.new
    snmp.tag_number = ASN1::BER::UniversalTags::Sequence
    snmp.children = {ver, com, pdu}
    snmp
  end

  # IO serialisation support
  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    self.class.new(io.read_bytes(ASN1::BER))
  end

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    self.to_ber.write(io)
  end
end
