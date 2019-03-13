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

  getter pdu : PDU | TrapPDU
  property version : Version
  property request : Request
  property community : String
end

require "./snmp/pdu"
