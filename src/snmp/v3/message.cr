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
    if snmp[3].tag == UniversalTags::Sequence
      @scoped_pdu = ScopedPDU.new(snmp[3])
    elsif security
      @scoped_pdu = ScopedPDU.new(security.decode(snmp[3]))
    else
      raise "session required to decode PDU"
    end

    # For compatibility with SNMPv2 Message class
    @request = @scoped_pdu.request
    @community = @scoped_pdu.engine_id
    @pdu = @scoped_pdu.pdu
  end

  PRIVNONE           = ASN1::BER.new.set_string("", tag: UniversalTags::OctetString)
  MSG_MAX_SIZE       = ASN1::BER.new.set_integer(65507)
  MSG_SECURITY_MODEL = ASN1::BER.new.set_integer(SecurityModel::User.to_i)
  MSG_VERSION        = ASN1::BER.new.set_integer(Version::V3.to_i)

  def self.encode(pdu : ScopedPDU, security : Security, engine_boots = 0, engine_time = 0)
    scoped_pdu, salt_param = security.encode(pdu.to_ber, salt: PRIVNONE, engine_boots: engine_boots, engine_time: engine_time)

    security_params = SecurityParams.new(
      security.username,
      security.engine_id,
      engine_boots,
      engine_time,
      salt_param
    )

    # Build the headers
    message_flags = ASN1::BER.new.set_integer((MessageFlags::Reportable | security.security_level).to_i)
    message_flags.tag_number = UniversalTags::OctetString
    message_id    = ASN1::BER.new.set_integer(rand(2147483647))

    headers = ASN1::BER.new
    headers.tag_number = UniversalTags::Sequence
    headers.children = {
      message_id,
      MSG_MAX_SIZE,
      message_flags,
      MSG_SECURITY_MODEL
    }

    # Build the complete message
    encoded = ASN1::BER.new
    encoded.tag_number = UniversalTags::Sequence
    encoded.children = {
      MSG_VERSION,
      headers,
      sec_params.to_ber,
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

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    self.to_ber.write(io)
  end

  # TODO::
  #def initialize(@version, @message_id, @remote_max_size, @flags, @security_model, )
    #@pdu = PDU.new(request_id, error_status, error_index)
  #end

  property id : Int32
  property max_size : Int32
  property flags : MessageFlags
  property security_model : SecurityModel
  property security_params : SecurityParams
  property scoped_pdu : ScopedPDU
end
