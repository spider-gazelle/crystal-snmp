require "./security"
require "./scoped_pdu"
require "./security_params"

class SNMP::V3::Message < SNMP::Message
  # SNMPv3 message flags describing the features used
  @[Flags]
  enum MessageFlags
    # privacy without authentication is not allowed
    Authentication

    # encryption applied?
    Privacy

    # Report PDU must be returned to the sender under those conditions that can cause the generation of a Report PDU
    # when the flag is zero, a Report PDU may not be sent.
    # The reportableFlag is set to 1 by the sender in all messages containing a request (Get, Set) or an Inform, and set to 0 for messages containing a Response, a Trap, or a Report PDU
    # It is used only in cases in which the PDU portion of the message cannot be decoded (for example, when decryption fails because of incorrect key)
    Reportable
  end

  enum SecurityModel
    # Any = 0
    SNMPv1
    SNMPv2

    # When an SNMP message contains a payload that expects a response (for example, a Get, GetNext, GetBulk, Set, or Inform PDU), then the receiver of such messages is authoritative.
    # When an SNMP message contains a payload that does not expect a response (for example, an SNMPv2-Trap, Response, or Report PDU), then the sender of such a message is authoritative.
    User
    Transport # DTLS
  end

  def initialize(snmp : Array(ASN1::BER), session = nil)
    # reference: http://www.tcpipguide.com/free/t_SNMPVersion3SNMPv3MessageFormat.htm
    @version = Version.from_value(snmp[0].get_integer)

    # A unique identifier used between two SNMP entities to coordinate request and response messages
    @id = snmp[1].get_integer.to_i

    # This is the maximum segment size that the sender can accept from another SNMP engine
    @max_size = snmp[2].get_integer.to_i
    @flags = MessageFlags.new(snmp[3].get_bytes[0].to_i)
    @security_model = SecurityModel.new(snmp[4].get_integer.to_i)
    @security = SecurityParams.new(snmp[5])

    # This data is encrypted
    @scoped_pdu = decode(snmp[-1], session)

    # For compatibility with SNMPv2 Message class
    @request = @scoped_pdu.request
    @community = @scoped_pdu.engine_id
    @pdu = @scoped_pdu.pdu
  end

  private def decode(pdu : ASN1::BER, session) : ScopedPDU
    if @flags.authentication?
      if session
        session.decode(pdu)
      else
        raise "session required to decode PDU"
      end
    else
      @scoped_pdu = ScopedPDU.new(pdu)
    end
  end

  def self.encode(pdu : ScopedPDU, security : Security)

  end

  # TODO::
  #def initialize(@version, @message_id, @remote_max_size, @flags, @security_model, )
    #@pdu = PDU.new(request_id, error_status, error_index)
  #end

  property id : Int32
  property max_size : Int32
  property flags : MessageFlags
  property security_model : SecurityModel
  property security : SecurityParams
  property scoped_pdu : ScopedPDU
end
