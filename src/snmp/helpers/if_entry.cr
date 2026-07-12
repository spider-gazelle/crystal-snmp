# https://www.alvestrand.no/objectid/1.3.6.1.2.1.2.2.1.html
class SNMP
  # http://www.net-snmp.org/docs/mibs/interfaces.html#ifAdminStatus
  enum IfAdminStatus
    Up      = 1
    Down
    Testing
  end

  enum IfOperStatus
    Up             = 1
    Down
    Testing
    Unknown
    Dormant
    NotPresent
    LowerLayerDown
  end

  # https://www.alvestrand.no/objectid/1.3.6.1.2.1.2.2.1.3.html
  enum IfType
    Other                  = 1
    Regular1822
    HDH1822
    DDNx25
    RFC877x25
    EthernetCSMACD
    ISO88023CSMACD
    ISO88024TokenBus
    ISO88025TokenRing
    ISO88026Man
    StarLan
    Proteon10Mbit
    Proteon80Mbit
    HyperChannel
    FDDI
    LAPB
    SDLC
    DSL
    EL
    BasicISDN
    PrimaryISDN
    PropPointToPointSerial
    PPP
    SoftwareLoopback
    EON
    Ethernet3Mbit
    NSIP
    SLIP
    Ultra
    DS3
    SIP
    FrameRelay
  end

  class Helpers::IfEntry
    # Column-object OID (without the trailing ifIndex instance) => the setter that
    # decodes the varbind into a field. ifTable (RFC 1213, `…2.2.1`) plus the
    # ifXTable extension (RFC 2863, `…31.1.1.1`) with its 64-bit HC counters.
    # Anything not listed is silently ignored.
    COLUMNS = {
      # -- ifTable (1.3.6.1.2.1.2.2.1.x) --
      "1.3.6.1.2.1.2.2.1.1" => ->(e : IfEntry, v : VarBind) { e.index = v.get_integer },
      "1.3.6.1.2.1.2.2.1.2" => ->(e : IfEntry, v : VarBind) { e.descr = v.get_string },
      # The IANA ifType registry has hundreds of values; anything outside the
      # enum falls back to Other rather than crashing the parse.
      "1.3.6.1.2.1.2.2.1.3"  => ->(e : IfEntry, v : VarBind) { e.type = IfType.from_value?(v.get_integer) || IfType::Other },
      "1.3.6.1.2.1.2.2.1.4"  => ->(e : IfEntry, v : VarBind) { e.mtu = v.get_integer },
      "1.3.6.1.2.1.2.2.1.5"  => ->(e : IfEntry, v : VarBind) { e.speed = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.6"  => ->(e : IfEntry, v : VarBind) { e.phys_address = v.get_string },
      "1.3.6.1.2.1.2.2.1.7"  => ->(e : IfEntry, v : VarBind) { e.admin_status = IfAdminStatus.from_value?(v.get_integer) || IfAdminStatus::Up },
      "1.3.6.1.2.1.2.2.1.8"  => ->(e : IfEntry, v : VarBind) { e.oper_status = IfOperStatus.from_value?(v.get_integer) || IfOperStatus::Unknown },
      "1.3.6.1.2.1.2.2.1.9"  => ->(e : IfEntry, v : VarBind) { e.last_change = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.10" => ->(e : IfEntry, v : VarBind) { e.in_octets = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.11" => ->(e : IfEntry, v : VarBind) { e.in_ucast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.12" => ->(e : IfEntry, v : VarBind) { e.in_nucast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.13" => ->(e : IfEntry, v : VarBind) { e.in_discards = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.14" => ->(e : IfEntry, v : VarBind) { e.in_errors = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.15" => ->(e : IfEntry, v : VarBind) { e.in_unknown_protos = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.16" => ->(e : IfEntry, v : VarBind) { e.out_octets = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.17" => ->(e : IfEntry, v : VarBind) { e.out_ucast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.18" => ->(e : IfEntry, v : VarBind) { e.out_nucast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.19" => ->(e : IfEntry, v : VarBind) { e.out_discards = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.20" => ->(e : IfEntry, v : VarBind) { e.out_errors = v.get_unsigned32 },
      "1.3.6.1.2.1.2.2.1.21" => ->(e : IfEntry, v : VarBind) { e.out_qlen = v.get_unsigned32 },

      # -- ifXTable (1.3.6.1.2.1.31.1.1.1.x) --
      "1.3.6.1.2.1.31.1.1.1.1"  => ->(e : IfEntry, v : VarBind) { e.name = v.get_string },
      "1.3.6.1.2.1.31.1.1.1.2"  => ->(e : IfEntry, v : VarBind) { e.in_multicast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.31.1.1.1.3"  => ->(e : IfEntry, v : VarBind) { e.in_broadcast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.31.1.1.1.4"  => ->(e : IfEntry, v : VarBind) { e.out_multicast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.31.1.1.1.5"  => ->(e : IfEntry, v : VarBind) { e.out_broadcast_pkts = v.get_unsigned32 },
      "1.3.6.1.2.1.31.1.1.1.6"  => ->(e : IfEntry, v : VarBind) { e.hc_in_octets = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.7"  => ->(e : IfEntry, v : VarBind) { e.hc_in_ucast_pkts = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.8"  => ->(e : IfEntry, v : VarBind) { e.hc_in_multicast_pkts = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.9"  => ->(e : IfEntry, v : VarBind) { e.hc_in_broadcast_pkts = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.10" => ->(e : IfEntry, v : VarBind) { e.hc_out_octets = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.11" => ->(e : IfEntry, v : VarBind) { e.hc_out_ucast_pkts = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.12" => ->(e : IfEntry, v : VarBind) { e.hc_out_multicast_pkts = v.get_unsigned64 },
      "1.3.6.1.2.1.31.1.1.1.13" => ->(e : IfEntry, v : VarBind) { e.hc_out_broadcast_pkts = v.get_unsigned64 },
      # ifLinkUpDownTrapEnable is enabled(1)/disabled(2); the TruthValue columns
      # below are true(1)/false(2) — both map 1 => true.
      "1.3.6.1.2.1.31.1.1.1.14" => ->(e : IfEntry, v : VarBind) { e.link_up_down_trap_enabled = v.get_integer == 1 },
      "1.3.6.1.2.1.31.1.1.1.15" => ->(e : IfEntry, v : VarBind) { e.high_speed = v.get_unsigned32 },
      "1.3.6.1.2.1.31.1.1.1.16" => ->(e : IfEntry, v : VarBind) { e.promiscuous_mode = v.get_integer == 1 },
      "1.3.6.1.2.1.31.1.1.1.17" => ->(e : IfEntry, v : VarBind) { e.connector_present = v.get_integer == 1 },
      "1.3.6.1.2.1.31.1.1.1.18" => ->(e : IfEntry, v : VarBind) { e.alias_name = v.get_string },
      "1.3.6.1.2.1.31.1.1.1.19" => ->(e : IfEntry, v : VarBind) { e.counter_discontinuity_time = v.get_unsigned32 },
    }

    def initialize(pdu : SNMP::PDU)
      pdu.varbinds.each do |varbind|
        # The OID carries the ifIndex instance - e.g. "1.3.6.1.2.1.2.2.1.1.26";
        # drop it to get the column-object OID.
        column = varbind.oid.split(".")[0..-2].join(".")
        COLUMNS[column]?.try &.call(self, varbind)
      end
    end

    # ifTable
    property index = 0_i64
    property descr = ""
    property type = IfType::EthernetCSMACD
    property mtu = 0_i64
    property speed = 0_u32
    property phys_address = ""
    property admin_status = IfAdminStatus::Up
    property oper_status = IfOperStatus::Unknown
    property last_change = 0_u32
    property in_octets = 0_u32
    property in_ucast_pkts = 0_u32
    property in_nucast_pkts = 0_u32
    property in_discards = 0_u32
    property in_errors = 0_u32
    property in_unknown_protos = 0_u32
    property out_octets = 0_u32
    property out_ucast_pkts = 0_u32
    property out_nucast_pkts = 0_u32
    property out_discards = 0_u32
    property out_errors = 0_u32
    property out_qlen = 0_u32

    # ifXTable (RFC 2863) — identity + 64-bit high-capacity counters
    property name = ""
    property in_multicast_pkts = 0_u32
    property in_broadcast_pkts = 0_u32
    property out_multicast_pkts = 0_u32
    property out_broadcast_pkts = 0_u32
    property hc_in_octets = 0_u64
    property hc_in_ucast_pkts = 0_u64
    property hc_in_multicast_pkts = 0_u64
    property hc_in_broadcast_pkts = 0_u64
    property hc_out_octets = 0_u64
    property hc_out_ucast_pkts = 0_u64
    property hc_out_multicast_pkts = 0_u64
    property hc_out_broadcast_pkts = 0_u64
    property? link_up_down_trap_enabled = false
    property high_speed = 0_u32
    property? promiscuous_mode = false
    property? connector_present = false
    property alias_name = ""
    property counter_discontinuity_time = 0_u32
  end
end
