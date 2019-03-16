require "bindata/asn1"

class SNMP
  # SNMP version codes
  enum Version
    V1
    V2C
    V3 = 3
  end

  enum Request
    GetRequest
    GetNext
    Response
    SetRequest
    V1_Trap
    GetBulk
    Inform
    V2_Trap
    Report
  end

  enum GenericTrap
    ColdStart
    WarmStart
    LinkDown
    LinkUp
    AuthenticationFailure
    EGPNeighborLoss
    EnterpriseSpecific
  end

  enum ErrorStatus
    NoError
    TooBig
    NoSuchName
    BadValue
    ReadOnly
    GenErr
  end

  # Custom SNMP tags on varbinds
  enum AppTags
    IPAddress
    Counter32
    Gauge32 # unsigned integer
    TimeTicks
    Opaque
    # missing 5
    Counter64 = 6
  end

  # Error context tags on varbinds
  enum ContextTags
    NoSuchObject
    NoSuchInstance
    EndOfMibView
  end

  def initialize(ber : ASN1::BER)
    snmp = ber.children
    @version = Version.from_value(snmp[0].get_integer)
    @community = snmp[1].get_string
    @request = Request.from_value(snmp[2].tag_number)

    if @version == Version::V3
      raise "not supported"
    elsif @request == Request::V1_Trap
      @pdu = V1Trap.new(snmp[2])
    else
      case @request
      when Request::V2_Trap
        @pdu = Trap.new(snmp[2])
      else
        @pdu = PDU.new(snmp[2])
      end
    end
  end

  def initialize(@version, @community, @request, request_id = 0, error_status = ErrorStatus::NoError, error_index = 0)
    @pdu = PDU.new(request_id, error_status, error_index)
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

  def trap?
    {Request::V1_Trap, Request::V2_Trap, Request::Inform}.includes? @request
  end

  def expects_response?
    {Request::GetRequest, Request::GetNext, Request::SetRequest, Request::GetBulk, Request::Inform}.includes? @request
  end

  def build_reply
    self.class.new(@version, @community, Request::Response, @pdu.request_id)
  end

  # IO serialisatio support
  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    SNMP.new(io.read_bytes(ASN1::BER))
  end

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    # version
    ver = ASN1::BER.new
    ver.set_integer(@version.to_i)

    # community
    com = ASN1::BER.new
    com.set_string(@community, ASN1::BER::UniversalTags::OctetString)

    # build pdu
    pdu = @pdu.to_ber(@request.to_u8)

    # write SNMP sequence
    snmp = ASN1::BER.new
    snmp.tag_number = ASN1::BER::UniversalTags::Sequence
    snmp.children = {ver, com, pdu}
    snmp.write(io)
  end
end

require "./snmp/pdu"
require "./snmp/trap"
require "./snmp/v1_trap"
require "./snmp/varbind"
require "./snmp/data_types"
