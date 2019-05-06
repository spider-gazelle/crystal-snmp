class SNMP::V3::Session
  def initialize(@username = "", @auth_protocol = Security::AuthProtocol::MD5, @priv_protocol = Security::PrivacyProtocol::DES, @auth_password = "", @priv_password = "")
    @engine_id = ""
    @engine_boots = 0
    @engine_time = 0

    @security = V3::Security.new(
      @username,
      @engine_id,
      @auth_protocol,
      @auth_password,
      @priv_protocol,
      @priv_password
    )
  end

  getter engine_id : String
  getter username : String
  getter auth_protocol : Security::AuthProtocol
  getter priv_protocol : Security::PrivacyProtocol
  getter auth_password : String
  getter priv_password : String
  getter timeliness : Int64 = 0_i64
  getter session_created : Int64 = 0_i64
  getter engine_time : Int32
  getter engine_boots : Int32

  # Timeliness is part of SNMP V3 Security
  # The topic is described very nice here https://www.snmpsharpnet.com/?page_id=28
  # https://www.ietf.org/rfc/rfc2574.txt 1.4.1 Timeliness
  # The probe is outdated after 150 seconds which results in a PDU Error, therefore it should expire before that and be renewed
  # The 150 Seconds is specified in https://www.ietf.org/rfc/rfc2574.txt 2.2.3
  TIMELINESS_THRESHOLD = 140_i64

  def must_revalidate?
    empty_id = @engine_id.empty?
    return true if empty_id
    return empty_id if @security.security_level == MessageFlags::None
    (Time.monotonic.to_i - @timeliness) >= TIMELINESS_THRESHOLD
  end

  def engine_validation_probe
    security_params = SecurityParams.new
    scoped_pdu = ScopedPDU.new(SNMP::Request::Get, SNMP::PDU.new)
    V3::Message.new(scoped_pdu, security_params, security_model: SecurityModel::Transport)
  end

  def validate(message : V3::Message)
    @security.engine_id = @engine_id = message.community
    @engine_boots = message.security_params.engine_boots
    @engine_time = message.security_params.engine_time
    @timeliness = Time.monotonic.to_i
  end

  def prepare(message : V3::Message) : ASN1::BER
    # Encrypt the scoped PDU as required
    pdu = message.scoped_pdu.to_ber
    encrypted_pdu, priv_salt = @security.encode(pdu, @engine_time, @engine_boots)
    message.security_params.priv_param = priv_salt
    message.security_params.engine_time = @engine_time
    message.security_params.engine_boots = @engine_boots

    # Sign the message
    message.sign(@security, encrypted_pdu)

    # Generate the final datagram
    message.to_ber(encrypted_pdu)
  end

  def parse(message : ASN1::BER, security = @security) : V3::Message
    snmp = message.children
    version = Version.from_value(snmp[0].get_integer)

    raise "SNMP version mismatch" unless version == Version::V3

    V3::Message.new(snmp, security)
  end

  # Note:: only used when being queried
  def reboot
    @engine_boots += 1
    @engine_time = 0
    @session_created = Time.monotonic.to_i
  end

  def update_time
    @engine_time = (Time.monotonic.to_i - @session_created).to_i
  end
end
