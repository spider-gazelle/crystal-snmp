class SNMP::Session
  def initialize(@community = "public")
  end

  property community : String

  # Maintain compatibility with V3 session
  def must_revalidate?
    false
  end

  def engine_validation_probe : V3::Message
    raise "engine probes are not required for SNMP V2C"
  end

  def validate(message : V3::Message)
    self
  end

  def validate(message : ASN1::BER)
    self
  end

  def reboot
    0_i64
  end

  def update_time
    0_i64
  end

  def prepare(message : Message) : ASN1::BER
    message.to_ber
  end

  def parse(message : ASN1::BER, security = nil) : SNMP::Message
    snmp = message.children
    version = Version.from_value(snmp[0].get_integer)

    raise "SNMP version mismatch, expected V2C got #{version}" unless version < Version::V3

    SNMP::Message.new(snmp)
  end

  def get(oid, request_id = rand(2147483647))
    SNMP::Message.new(@community, Request::Get, VarBind.new(oid), request_id)
  end

  def get_next(oid, request_id = rand(2147483647))
    message = get(oid, request_id)
    message.request = Request::GetNext
    message
  end

  # TODO:: requires better support for SNMP values such as Counter32, Counter64, Gauge32, OID, Timeticks etc
  def set(oid, value, request_id = rand(2147483647))
    data = value.is_a?(VarBind) ? value : VarBind.new(oid)

    case value
    when String
      data.value.set_string(value)
    when Int
      data.value.set_integer(value)
      # TODO::
      # when Float
      # when Socket::IPAddress
    when Bool
      data.value.set_boolean(value)
    when Nil
      data.value.tag_number = UniversalTags::Null
    when ASN1::BER
      data.value = value
    when VarBind
      data.oid = oid
    else
      raise "unsupported varbind value. For complex values pass a pre-constructed `ASN1::BER`"
    end

    SNMP::Message.new(@community, Request::Set, data, request_id)
  end
end
