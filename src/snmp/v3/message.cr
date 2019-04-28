require "./security"
require "./scoped_pdu"
require "./security_params"

class SNMP::V3::Message < SNMP::Message
  def initialize(snmp : Array(ASN1::BER), session = nil)
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
    @security = SecurityParams.new(snmp[2])

    # This data is encrypted
    @scoped_pdu = decode(snmp[3], session)

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

  AUTHNONE           = ASN1::BER.new.set_string("\x00" * 12, tag: UniversalTags::OctetString)
  PRIVNONE           = ASN1::BER.new.set_string("", tag: UniversalTags::OctetString)
  MSG_MAX_SIZE       = ASN1::BER.new.set_integer(65507)
  MSG_SECURITY_MODEL = ASN1::BER.new.set_integer(SecurityModel::User.to_i)
  MSG_VERSION        = ASN1::BER.new.set_integer(Version::V3.to_i)

  def self.encode(pdu : ScopedPDU, security : Security, engine_boots = 0, engine_time = 0)
    scoped_pdu, salt_param = security.encode(pdu.to_ber, salt: PRIVNONE, engine_boots: engine_boots, engine_time: engine_time)

    # TODO:: replace with SecurityParams.new
    security_params = ASN1::BER.new
    security_params.tag_number = ASN1::BER::UniversalTags::Sequence
    security_params.children = {
      ASN1::BER.new.set_octet_string(security.engine_id),
      ASN1::BER.new.set_integer(engine_boots),
      ASN1::BER.new.set_integer(engine_time),
      ASN1::BER.new.set_string(security.username, tag: UniversalTags::OctetString),
      AUTHNONE,
      salt_param
    }

    # security params are stored in a generic octet string BER
    temp = IO::Memory.new
    temp.write_bytes security_params
    sec_params = ASN1::BER.new.set_string("", tag: UniversalTags::OctetString)
    sec_params.payload = temp.to_slice

    # Build the headers
    message_flags = ASN1::BER.new.set_integer((MessageFlags::Reportable | security.security_level).to_i)
    message_flags.tag_number = UniversalTags::OctetString
    message_id    = ASN1::BER.new.set_integer(rand(2147483647))

    headers = ASN1::BER.new
    headers.tag_number = ASN1::BER::UniversalTags::Sequence
    headers.children = {
      message_id,
      MSG_MAX_SIZE,
      message_flags,
      MSG_SECURITY_MODEL
    }

    # Build the complete message
    encoded = ASN1::BER.new
    encoded.tag_number = ASN1::BER::UniversalTags::Sequence
    encoded.children = {
      MSG_VERSION,
      headers,
      sec_params,
      scoped_pdu
    }

    # Sign the request
    signature = security.sign(encoded)
    if signature
      auth_salt = ASN1::BER.new.set_string(signature, tag: UniversalTags::OctetString)
      # TODO:: need to so this efficiently
      # encoded.sub!(AUTHNONE.to_der, auth_salt.to_der)
    end
    encoded
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
