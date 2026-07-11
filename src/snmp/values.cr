require "./data_types"

# Typed SNMP values for `Session#set` / `PDU` construction. Each wraps a value
# and knows how to encode itself as an application-tagged (RFC 3416) BER, so a
# caller can set e.g. a Counter or a TimeTicks without hand-building the BER.
module SNMP::TypedValue
  abstract def to_ber : ASN1::BER

  # Build an application-class primitive carrying *payload* under *app_tag*.
  private def application_ber(app_tag : AppTags, payload : ASN1::BER) : ASN1::BER
    payload.tag_class = ASN1::BER::TagClass::Application
    payload.tag_number = app_tag.to_i
    payload
  end
end

# Counter32 (RFC 2578) — a non-negative wrapping 32-bit counter.
struct SNMP::Counter32
  include TypedValue

  def initialize(@value : UInt32)
  end

  def to_ber : ASN1::BER
    application_ber(AppTags::Counter32, SNMP.set_unsigned32(@value))
  end
end

# Gauge32 / Unsigned32 (RFC 2578) — a non-negative 32-bit value that latches.
struct SNMP::Gauge32
  include TypedValue

  def initialize(@value : UInt32)
  end

  def to_ber : ASN1::BER
    application_ber(AppTags::Gauge32, SNMP.set_unsigned32(@value))
  end
end

# TimeTicks (RFC 2578) — hundredths of a second since an epoch.
struct SNMP::TimeTicks
  include TypedValue

  def initialize(@value : UInt32)
  end

  def to_ber : ASN1::BER
    application_ber(AppTags::TimeTicks, SNMP.set_unsigned32(@value))
  end
end

# Counter64 (RFC 2578) — a non-negative wrapping 64-bit counter (SNMPv2+).
struct SNMP::Counter64
  include TypedValue

  def initialize(@value : UInt64)
  end

  def to_ber : ASN1::BER
    application_ber(AppTags::Counter64, SNMP.set_unsigned64(@value))
  end
end

# IpAddress (RFC 2578) — a 4-octet IPv4 address.
struct SNMP::IpAddress
  include TypedValue

  @bytes : Bytes

  def initialize(@bytes : Bytes)
    raise ArgumentError.new("IpAddress requires exactly 4 bytes, got #{@bytes.size}") unless @bytes.size == 4
  end

  # Accept a dotted-quad string, e.g. "192.168.1.254".
  def initialize(dotted : String)
    octets = dotted.split('.')
    raise ArgumentError.new("invalid IPv4 address #{dotted.inspect}") unless octets.size == 4
    @bytes = Bytes.new(4) { |i| octets[i].to_u8 }
  end

  def to_ber : ASN1::BER
    ber = ASN1::BER.new
    ber.payload = @bytes
    application_ber(AppTags::IPAddress, ber)
  end
end

# Opaque (RFC 2578) — an application-wrapped arbitrary byte string.
struct SNMP::Opaque
  include TypedValue

  def initialize(@bytes : Bytes)
  end

  def to_ber : ASN1::BER
    ber = ASN1::BER.new
    ber.payload = @bytes
    application_ber(AppTags::Opaque, ber)
  end
end

# An OBJECT IDENTIFIER value (universal tag), for setting OID-valued objects.
struct SNMP::OID
  include TypedValue

  def initialize(@oid : String)
  end

  def to_ber : ASN1::BER
    ASN1::BER.new.set_object_id(@oid)
  end
end
