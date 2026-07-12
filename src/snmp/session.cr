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
    snmp = SNMP.ber_fields(message, 1, "SNMP message")
    version = SNMP.decode_enum(Version, snmp[0].get_integer, "SNMP version")

    raise SNMP::VersionError.new("SNMP version mismatch, expected V2C got #{version}") unless version < Version::V3

    SNMP::Message.new(snmp)
  end

  def get(oid, request_id = rand(2147483647))
    SNMP::Message.new(@community, Request::Get, VarBind.new(oid), request_id)
  end

  # Multi-varbind Get: one GetRequest carrying every OID (RFC 3416 allows a PDU
  # to bind several variables), answered by a single Response with N varbinds.
  def get(oids : Enumerable(String), request_id = rand(2147483647))
    varbinds = oids.map { |oid| VarBind.new(oid) }.to_a
    SNMP::Message.new(@community, Request::Get, varbinds, request_id)
  end

  def get_next(oid, request_id = rand(2147483647))
    message = get(oid, request_id)
    message.request = Request::GetNext
    message
  end

  def get_next(oids : Enumerable(String), request_id = rand(2147483647))
    message = get(oids, request_id)
    message.request = Request::GetNext
    message
  end

  # GetBulk (RFC 3416): retrieve up to *max_repetitions* successors for each
  # repeating varbind in one round-trip. The first *non_repeaters* OIDs are
  # treated as plain GetNext, the rest as repeaters.
  def get_bulk(oids : Enumerable(String), non_repeaters = 0, max_repetitions = 10, request_id = rand(2147483647))
    varbinds = oids.map { |oid| VarBind.new(oid) }.to_a
    message = SNMP::Message.new(@community, Request::GetBulk, varbinds, request_id)
    message.non_repeaters = non_repeaters
    message.max_repetitions = max_repetitions
    message
  end

  def set(oid, value, request_id = rand(2147483647))
    SNMP::Message.new(@community, Request::Set, to_varbind(oid, value), request_id)
  end

  # Standard first two varbinds of an SNMPv2 notification (RFC 3416 4.2.6).
  SYS_UPTIME_OID    = "1.3.6.1.2.1.1.3.0"
  SNMP_TRAP_OID_OID = "1.3.6.1.6.3.1.1.4.1.0"

  # Build an SNMPv2-Trap: sysUpTime.0 + snmpTrapOID.0 followed by *varbinds*.
  def trap_v2(oid, uptime = 0, varbinds : Array(VarBind) = [] of VarBind, request_id = rand(2147483647))
    SNMP::Message.new(@community, Request::V2_Trap, notification_varbinds(oid, uptime, varbinds), request_id)
  end

  # Build an Inform (same shape as a v2 trap, but confirmed by the receiver).
  def inform(oid, uptime = 0, varbinds : Array(VarBind) = [] of VarBind, request_id = rand(2147483647))
    SNMP::Message.new(@community, Request::Inform, notification_varbinds(oid, uptime, varbinds), request_id)
  end

  # Build an RFC 1157 SNMPv1 Trap (its own wire structure). *enterprise* is the
  # enterprise OID, *agent_address* a dotted-quad IPv4 string.
  def trap_v1(enterprise, agent_address, generic_trap : GenericTrap, specific_trap = 0, uptime = 0, varbinds : Array(VarBind) = [] of VarBind, request_id = rand(2147483647))
    pdu = V1Trap.new(agent_address, generic_trap, specific_trap.to_i32,
      oid: enterprise, time_ticks: uptime.to_u32, varbinds: varbinds, request_id: request_id)
    SNMP::Message.new(@community, Request::V1_Trap, pdu, version: Version::V1)
  end

  private def notification_varbinds(oid, uptime, extra : Array(VarBind)) : Array(VarBind)
    uptime_vb = VarBind.new(SYS_UPTIME_OID)
    uptime_vb.value = TimeTicks.new(uptime.to_u32).to_ber

    trap_oid_vb = VarBind.new(SNMP_TRAP_OID_OID)
    trap_oid_vb.value = OID.new(oid).to_ber

    [uptime_vb, trap_oid_vb] + extra
  end

  # Multi-varbind Set: one SetRequest assigning every OID => value pair. The Hash
  # keeps insertion order, so the varbinds go out in the order they were given.
  def set(values : Hash(String, _), request_id = rand(2147483647))
    varbinds = values.map { |oid, value| to_varbind(oid, value) }
    SNMP::Message.new(@community, Request::Set, varbinds, request_id)
  end

  # Encode a single OID => value assignment into a VarBind. Accepts the typed
  # SNMP values (`TypedValue`), the Crystal primitives, a raw `ASN1::BER`, or a
  # pre-built `VarBind`.
  private def to_varbind(oid, value) : VarBind
    data = value.is_a?(VarBind) ? value : VarBind.new(oid)

    case value
    when TypedValue
      data.value = value.to_ber
    when String
      data.value.set_string(value)
    when Int
      data.value.set_integer(value)
    when Bool
      data.value.set_boolean(value)
    when Nil
      data.value.tag_number = UniversalTags::Null
    when ASN1::BER
      data.value = value
    when VarBind
      data.oid = oid
    else
      raise ArgumentError.new("unsupported varbind value. For complex values pass a pre-constructed `ASN1::BER`")
    end

    data
  end
end
