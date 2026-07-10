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

  # Multi-varbind Get: one round-trip binding every OID; the Response carries a
  # varbind per requested OID.
  def get(oids : Enumerable(String)) : SNMP::Message
    msg : SNMP::Message? = nil
    with_socket do |sock|
      msg = get(oids, sock)
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

  private def get(oids : Enumerable(String), sock : UDPSocket) : SNMP::Message
    check_validation_probe(sock)

    message = session.get(oids)
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

  # Multi-varbind GetNext: advances every supplied OID in one round-trip.
  def get_next(oids : Enumerable(String)) : SNMP::Message
    msg : SNMP::Message? = nil

    with_socket do |sock|
      msg = get_next(oids, sock)
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

  private def get_next(oids : Enumerable(String), sock : UDPSocket) : SNMP::Message
    check_validation_probe(sock)

    message = session.get_next(oids)
    message = session.prepare(message) if message.is_a?(SNMP::V3::Message)

    sock.write_bytes message
    sock.flush
    session.parse(sock.read_bytes(ASN1::BER))
  end

  # GetBulk: one round-trip returning up to *max_repetitions* successors per
  # repeating OID. Returns the raw Response message (its PDU holds every varbind).
  def get_bulk(oids : Enumerable(String), non_repeaters = 0, max_repetitions = 10) : SNMP::Message
    msg : SNMP::Message? = nil
    with_socket do |sock|
      msg = get_bulk(oids, sock, non_repeaters, max_repetitions)
    end

    raise Error.new("Failed to read message") if msg.nil?
    msg
  end

  private def get_bulk(oids : Enumerable(String), sock : UDPSocket, non_repeaters, max_repetitions) : SNMP::Message
    check_validation_probe(sock)

    message = session.get_bulk(oids, non_repeaters, max_repetitions)
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
        # Stop at the RFC 3416 endOfMibView exception (not merely an empty value).
        break if msg.value.end_of_mib_view?

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
        # Stop at the RFC 3416 endOfMibView exception (not merely an empty value).
        break if msg.value.end_of_mib_view?

        yield msg
        msg = get_next(msg.oid, sock)
      end
    end
    self
  end

  # Walk *oid*'s subtree using GetBulk (fewer round-trips than GetNext), yielding
  # each in-subtree `VarBind`. Stops at `endOfMibView` or the first varbind that
  # leaves the subtree. *max_repetitions* bounds the varbinds fetched per request.
  def bulk_walk(oid : String, max_repetitions = 10, &)
    with_socket do |sock|
      current = oid
      loop do
        varbinds = get_bulk({current}, sock, 0, max_repetitions).varbinds
        # No varbinds at all: nothing more to fetch (defensive against a stuck agent).
        break if varbinds.empty?

        advanced = false
        varbinds.each do |varbind|
          # End of the MIB, or the subtree is exhausted (GetBulk overshoots it).
          return self if varbind.end_of_mib_view? || !self.class.oid_within?(varbind.oid, oid)

          yield varbind
          current = varbind.oid
          advanced = true
        end

        # A full response with no in-subtree progress would loop forever.
        break unless advanced
      end
    end
    self
  end

  # Non-block form: collect the whole subtree into an array of `VarBind`.
  def bulk_walk(oid : String, max_repetitions = 10) : Array(SNMP::VarBind)
    results = [] of SNMP::VarBind
    bulk_walk(oid, max_repetitions) { |varbind| results << varbind }
    results
  end

  protected def check_validation_probe(sock)
    if session.must_revalidate?
      sock.write_bytes session.engine_validation_probe
      sock.flush
      session.validate sock.read_bytes(ASN1::BER)
    end
  end
end
