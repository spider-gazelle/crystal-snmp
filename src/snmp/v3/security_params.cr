class SNMP::V3::SecurityParams
  def initialize(params : ASN1::BER)
    parts = params.children

    # 10-64 Hex characters
    @engine_id = parts[0].get_octet_string

    # the number of times that this SNMP engine has initialized or reinitialized itself since its initial configuration.
    @engine_boots = SNMP.get_unsigned32(parts[1])

    # the number of seconds since this authoritative SNMP engine last incremented the snmpEngineBoots object
    @engine_time = SNMP.get_unsigned32(parts[2])
    @username = parts[3].get_string

    # TODO:: check for parts[4/5].tag == UniversalTags::Null
    #@auth_param = parts[4].
    #@priv_param = parts[5].
  end

  def initialize(@username, @engine_id = "", @engine_boots = 0, @engine_time = 0)
  end

  property engine_id : String
  property engine_boots : UInt32
  property engine_time : UInt32
  property username : String

  def to_ber
    engine = ASN1::BER.new.set_octet_string(@engine_id)
    boots = SNMP.set_unsigned32(@engine_boots)
    time = SNMP.set_unsigned32(@engine_time)
    user = ASN1::BER.new.set_string(@username)

    # TODO:: auth privs

    snmp = ASN1::BER.new
    snmp.tag_number = ASN1::BER::UniversalTags::Sequence
    snmp.children = {engine, boots, time, user}
    snmp
  end
end
