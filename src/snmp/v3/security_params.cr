class SNMP::V3::SecurityParams
  def initialize(params : ASN1::BER)
    temp = IO::Memory.new(params.payload)
    security = temp.read_bytes(ASN1::BER)
    parts = security.children

    # 10-64 Hex characters
    @engine_id = parts[0].get_octet_string

    # the number of times that this SNMP engine has initialized or reinitialized itself since its initial configuration.
    @engine_boots = parts[1].get_integer.to_i

    # the number of seconds since this authoritative SNMP engine last incremented the snmpEngineBoots object
    @engine_time = parts[2].get_integer.to_i
    @username = parts[3].get_string

    # Salts / hashes
    @auth_param = parts[4].get_bytes
    @priv_param = parts[5].get_bytes
  end

  AUTHNONE = ASN1::BER.new.set_string("\x00" * 12, tag: UniversalTags::OctetString)
  def initialize(@username, @engine_id = "", @engine_boots = 0, @engine_time = 0, @priv_param = "".to_slice, @auth_param = AUTHNONE)
  end

  property engine_id : String
  property engine_boots : Int32
  property engine_time : Int32
  property username : String
  property auth_param : Bytes
  property priv_param : Bytes

  def to_ber(auth = @auth_param)
    engine = ASN1::BER.new.set_octet_string(@engine_id)
    boots = ASN1::BER.new.set_integer(@engine_boots)
    time = ASN1::BER.new.set_integer(@engine_time)
    user = ASN1::BER.new.set_string(@username, tag: UniversalTags::OctetString)

    aparam = ASN1::BER.new
    aparam.payload = auth
    aparam.tag_number = UniversalTags::OctetString

    pparam = ASN1::BER.new
    pparam.payload = @priv_param
    pparam.tag_number = UniversalTags::OctetString

    # Build the params sequence
    params = ASN1::BER.new
    params.tag_number = UniversalTags::Sequence
    params.children = {engine, boots, time, user, aparam, pparam}

    # Security params are stored in a generic octet string BER
    temp = IO::Memory.new
    temp.write_bytes params
    sec_params = ASN1::BER.new
    sec_params.payload = temp.to_slice
    sec_params.tag_number = UniversalTags::OctetString
    sec_params
  end
end
