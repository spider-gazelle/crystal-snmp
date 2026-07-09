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
end
