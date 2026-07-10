class SNMP
  # Base class for every error raised by this library.
  class Error < Exception
  end

  # Raised when wire data cannot be decoded: malformed, truncated, or an
  # out-of-range enum/field value.
  class ParseError < Error
  end

  # Raised when a message's SNMP version does not match the session.
  class VersionError < ParseError
  end

  # Raised when a request times out waiting for a response.
  class TimeoutError < Error
  end

  # Decode an enum value read off the wire, raising `ParseError` on an unknown value
  # instead of the raw `ArgumentError` that `Enum.from_value` would raise.
  def self.decode_enum(type : T.class, value, name : String) : T forall T
    type.from_value?(value) || raise ParseError.new("unknown #{name} value: #{value}")
  end

  # Return the children of *ber*, raising `ParseError` when there are fewer than
  # *min* (a truncated / malformed structure) instead of a later `IndexError`.
  def self.ber_fields(ber : ASN1::BER, min : Int32, name : String) : Array(ASN1::BER)
    fields = ber.children
    raise ParseError.new("truncated #{name}: expected at least #{min} fields, got #{fields.size}") if fields.size < min
    fields
  end
end
