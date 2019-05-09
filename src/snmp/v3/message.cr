require "./session"
require "./security"
require "./scoped_pdu"
require "./security_params"

class SNMP::V3::Message < SNMP::Message
  def initialize(snmp : Array(ASN1::BER), security = nil)
    # reference: http://www.tcpipguide.com/free/t_SNMPVersion3SNMPv3MessageFormat.htm
    # version, headers, security, encrypted pdu
    @version = Version.from_value(snmp[0].get_integer)
    headers = snmp[1].children

    # A unique identifier used between two SNMP entities to coordinate request and response messages
    @id = headers[0].get_integer.to_i

    # This is the maximum segment size that the sender can accept from another SNMP engine
    @max_size = headers[1].get_integer.to_i
    @flags = MessageFlags.new(headers[2].get_bytes[0].to_i)
    @security_model = SecurityModel.new(headers[3].get_integer.to_i)

    # Extract security params
    @security_params = SecurityParams.new(snmp[2])

    # This data is encrypted if response is an OctetString
    if security
      if @flags.privacy?
        @scoped_pdu = ScopedPDU.new(security.decode(snmp[3], @security_params.priv_param, @security_params.engine_time, @security_params.engine_boots))
        verify(security, snmp[3])
      else
        @scoped_pdu = ScopedPDU.new(snmp[3])
        verify(security, snmp[3]) if @flags.authentication?
      end
    elsif snmp[3].tag == UniversalTags::Sequence
      @scoped_pdu = ScopedPDU.new(snmp[3])
    else
      raise "session security required to decode PDU"
    end

    # For compatibility with SNMPv2 Message class
    @community = @security_params.engine_id
    @request = @scoped_pdu.request
    @pdu = @scoped_pdu.pdu
  end

  def initialize(@scoped_pdu : ScopedPDU, @security_params : SecurityParams, security : Security? = nil, @security_model = SecurityModel::User, @id = rand(2147483647))
    @version = Version::V3
    @max_size = 65507
    if security
      @flags = security.security_level | MessageFlags::Reportable
    else
      @flags = MessageFlags::Reportable
    end

    @community = @security_params.engine_id
    @request = @scoped_pdu.request
    @pdu = @scoped_pdu.pdu
  end

  property id : Int32
  property max_size : Int32
  property flags : MessageFlags
  property security_model : SecurityModel
  property security_params : SecurityParams
  property scoped_pdu : ScopedPDU

  def engine_id
    @security_params.engine_id
  end

  def engine_id=(id)
    @security_params.engine_id = @community = id
  end

  def community=(id)
    @security_params.engine_id = @community = id
  end

  def request=(type : Request)
    @scoped_pdu.request = @request = type
  end

  def pdu=(pdu)
    @scoped_pdu.pdu = @pdu = pdu
  end

  def new_request_id
    @pdu.new_request_id
    @id = rand(2147483647)
  end

  AUTHNONE     = Bytes.new(12)
  PRIVNONE     = ASN1::BER.new.set_string("", tag: UniversalTags::OctetString)
  MSG_MAX_SIZE = ASN1::BER.new.set_integer(65507)
  MSG_VERSION  = ASN1::BER.new.set_integer(Version::V3.to_i)

  def verify(security, scoped_pdu = @scoped_pdu.to_ber)
    return if security.security_level == MessageFlags::None
    existing_signature, signature = sign(security, scoped_pdu)
    raise "invalid message authentication salt" unless existing_signature == signature
  end

  def sign(security, scoped_pdu = @scoped_pdu.to_ber)
    # ensure auth param is 0'd
    existing_signature = @security_params.auth_param
    @security_params.auth_param = AUTHNONE

    # Sign the request
    signature = security.sign(to_ber(scoped_pdu))
    @security_params.auth_param = signature

    {existing_signature, signature}
  end

  # The scoped PDU can be passed in as a BER for passing in encrypted values
  def to_ber(scoped_pdu = @scoped_pdu.to_ber)
    # Build the header
    message_flags = ASN1::BER.new.set_integer(@flags.to_i)
    message_flags.tag_number = UniversalTags::OctetString
    message_id = ASN1::BER.new.set_integer(@id)
    max = ASN1::BER.new.set_integer(@max_size)
    model = ASN1::BER.new.set_integer(@security_model.to_i)

    headers = ASN1::BER.new
    headers.tag_number = UniversalTags::Sequence
    headers.children = {
      message_id,
      max,
      message_flags,
      model
    }

    # Build the complete message
    encoded = ASN1::BER.new
    encoded.tag_number = UniversalTags::Sequence
    encoded.children = {
      MSG_VERSION,
      headers,
      @security_params.to_ber,
      scoped_pdu
    }

    encoded
  end
end
