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
    elsif @version == Version::V1 && @request == Request::V1_Trap
      @pdu = TrapPDU.new(snmp[2].children)
    else
      @pdu = PDU.new(snmp[2].children)
    end
  end

  def initialize(@version, @community, @request, request_id = 0, error_status = ErrorStatus::NoError, error_index = 0)
    @pdu = PDU.new(request_id, error_status, error_index)
  end

  getter pdu : PDU | TrapPDU
  property version : Version
  property request : Request
  property community : String

  def varbinds
    @pdu.varbinds
  end

  def trap?
    {Request::V1_Trap, Request::V2_Trap, Request::Inform}.includes? @request
  end

  def expects_response?
    {Request::GetRequest, Request::GetNext, Request::SetRequest, Request::GetBulk, Request::Inform}.includes? @request
  end

  def build_reply
    self.class.new(@version, @community, Request::Response, @pdu.request_id)
  end
end

require "./snmp/pdu"
require "./snmp/varbind"
require "./snmp/v1_trap"
