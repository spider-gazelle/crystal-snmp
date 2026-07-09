require "socket"
require "../snmp"

class SNMP::Client
  class Error < SNMP::Error
  end

  getter socket : UDPSocket
  getter session : SNMP::Session | SNMP::V3::Session
  getter host, timeout, port

  def initialize(@host : String, community = "public", @timeout = 3, @port = 161)
    @socket = UDPSocket.new
    socket.sync = false
    socket.read_timeout = timeout
    @session = SNMP::Session.new(community: community)
  end

  def initialize(@host : String, @session : SNMP::Session | SNMP::V3::Session, @timeout = 3, @port = 161)
    @socket = UDPSocket.new
    socket.sync = false
    socket.read_timeout = timeout
  end

  # True when *oid* is the *base* subtree or a descendant of it. Compares OID
  # arcs, not the raw string, so a sibling column (e.g. `.10`) that merely shares
  # a string prefix with `.1` is not treated as a child.
  def self.oid_within?(oid : String, base : String) : Bool
    oid == base || oid.starts_with?("#{base}.")
  end

  private def with_socket(&)
    if socket.closed?
      @socket = UDPSocket.new
      socket.sync = false
      socket.read_timeout = timeout
    end
    socket.connect(host, port)
    begin
      yield socket
    rescue ex : IO::TimeoutError
      raise SNMP::TimeoutError.new("no response from #{host}:#{port} within #{timeout}s", cause: ex)
    rescue ex : BinData::ParseError
      # A read timeout surfaces here as a BinData::ParseError wrapping IO::TimeoutError
      raise SNMP::TimeoutError.new("no response from #{host}:#{port} within #{timeout}s", cause: ex) if timed_out?(ex)
      raise SNMP::ParseError.new("failed to decode SNMP response from #{host}:#{port}: #{ex.message}", cause: ex)
    ensure
      socket.close
    end
  end

  private def timed_out?(error : Exception) : Bool
    cause = error.cause
    while cause
      return true if cause.is_a?(IO::TimeoutError)
      cause = cause.cause
    end
    false
  end

  def get(oid : String) : SNMP::Message
    msg : SNMP::Message? = nil
    with_socket do |sock|
      msg = get(oid, sock)
    end

    raise Error.new("Failed to read message") if msg.nil?
    msg
  end

  private def get(oid : String, sock : UDPSocket) : SNMP::Message
    check_validation_probe(sock)

    message = session.get(oid)
    message = session.prepare(message) if message.is_a?(SNMP::V3::Message)

    sock.write_bytes message
    sock.flush
    session.parse(sock.read_bytes(ASN1::BER))
  end

  def get_next(oid : String) : SNMP::Message
    msg : SNMP::Message? = nil

    with_socket do |sock|
      msg = get_next(oid, sock)
    end

    raise Error.new("Failed to read message") if msg.nil?
    msg
  end

  private def get_next(oid : String, sock : UDPSocket) : SNMP::Message
    check_validation_probe(sock)

    message = session.get_next(oid)
    message = session.prepare(message) if message.is_a?(SNMP::V3::Message)

    sock.write_bytes message
    sock.flush
    session.parse(sock.read_bytes(ASN1::BER))
  end

  def walk(oid : String) : Array(SNMP::Message)
    messages = [] of SNMP::Message
    with_socket do |sock|
      msg = get_next(oid, sock)

      # While the message is not nil and the returned oid is a child of the request
      while !msg.nil? && self.class.oid_within?(msg.oid, oid)
        # Break at END OF MIB
        break if msg.value.payload.empty?

        messages << msg
        msg = get_next(msg.oid, sock)
      end
    end
    messages
  end

  def walk(oid : String, &)
    with_socket do |sock|
      msg = get_next(oid, sock)

      # While the message is not nil and the returned oid is a child of the request
      while !msg.nil? && self.class.oid_within?(msg.oid, oid)
        # Break at END OF MIB
        break if msg.value.payload.empty?

        yield msg
        msg = get_next(msg.oid, sock)
      end
    end
    self
  end

  protected def check_validation_probe(sock)
    if session.must_revalidate?
      sock.write_bytes session.engine_validation_probe
      sock.flush
      session.validate sock.read_bytes(ASN1::BER)
    end
  end
end
