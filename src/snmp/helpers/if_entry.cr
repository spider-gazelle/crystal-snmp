# https://www.alvestrand.no/objectid/1.3.6.1.2.1.2.2.1.html
class SNMP
  class Helpers::IfEntry
    # ameba:disable Metrics/CyclomaticComplexity
    def initialize(pdu : SNMP::PDU)
      pdu.varbinds.each do |varbind|
        # As the OID includes the IfIndex - i.e. "1.3.6.1.2.1.2.2.1.1.26"
        case varbind.oid.split(".")[0..-2].join(".")
        when "1.3.6.1.2.1.2.2.1.1"
          @index = varbind.get_integer
        when "1.3.6.1.2.1.2.2.1.2"
          @descr = varbind.get_string
        when "1.3.6.1.2.1.2.2.1.3"
          @type = IfType.from_value(varbind.get_integer)
        when "1.3.6.1.2.1.2.2.1.4"
          @mtu = varbind.get_integer
        when "1.3.6.1.2.1.2.2.1.5"
          @speed = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.6"
          @phys_address = varbind.get_string
        when "1.3.6.1.2.1.2.2.1.7"
          @admin_status = IfAdminStatus.from_value(varbind.get_integer)
        when "1.3.6.1.2.1.2.2.1.8"
          @oper_status = IfOperStatus.from_value(varbind.get_integer)
        when "1.3.6.1.2.1.2.2.1.9"
          @last_change = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.10"
          @in_octets = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.11"
          @in_ucast_pkts = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.12"
          @in_nucast_pkts = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.13"
          @in_discards = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.14"
          @in_errors = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.15"
          @in_unknown_protos = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.16"
          @out_octets = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.17"
          @out_ucast_pkts = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.18"
          @out_nucast_pkts = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.19"
          @out_discards = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.20"
          @out_errors = varbind.get_unsigned32
        when "1.3.6.1.2.1.2.2.1.21"
          @out_qlen = varbind.get_unsigned32
        else
          # We are not sure what this entry is
          # safe to ignore
        end
      end
    end

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
  end

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
end
