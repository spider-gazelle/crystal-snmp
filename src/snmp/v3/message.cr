require "./security"
require "./scoped_pdu"

class SNMP::V3::Message < SNMP::Message
  # SNMPv3 message flags describing the features used
  @[Flags]
  enum MessageFlags
    Authentication
    Privacy
    Reportable
  end

  def initialize(snmp : Array(ASN1::BER))
    # reference: http://www.tcpipguide.com/free/t_SNMPVersion3SNMPv3MessageFormat.htm
    @version = Version.from_value(snmp[0].get_integer)
    @id = snmp[1].get_integer.to_i
    @max_size = snmp[2].get_integer.to_i
    @flags = MessageFlags.new(snmp[3].get_bytes[0].to_i)

    # TODO:: security model needs an enum:
    @security_model = snmp[4].get_integer.to_i
    @security_params = snmp[5..-2]

    # TODO:: This data is encrypted
    @scoped_pdu = ScopedPDU.new(snmp[-1])

    # For compatibility with SNMPv2 Message class
    @request = @scoped_pdu.request
    @community = @scoped_pdu.engine_id
    @pdu = @scoped_pdu.pdu
  end

  # TODO::
  #def initialize(@version, @message_id, @remote_max_size, @flags, @security_model, )
    #@pdu = PDU.new(request_id, error_status, error_index)
  #end

  property id : Int32
  property max_size : Int32
  property flags : MessageFlags
  property security_model : Int32
  property security_params : Array(ASN1::BER)
  property scoped_pdu : ScopedPDU
end
