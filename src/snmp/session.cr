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
end
