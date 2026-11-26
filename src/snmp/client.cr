require "socket"
require "../snmp"

class SNMP::Client
  class Error < SNMP::Error
  end

  private MAX_DATAGRAM_SIZE = 65_507
  @receive_buffer : Bytes?

  getter socket : UDPSocket
  getter session : SNMP::Session | SNMP::V3::Session
  getter host : String
  getter timeout : Int32
  getter port : Int32

  def initialize(@host : String, community = "public", @timeout = 3, @port = 161)
    @socket = build_socket
    @connected = false
    @session = SNMP::Session.new(community: community)
  end

  def initialize(@host : String, @session : SNMP::Session | SNMP::V3::Session, @timeout = 3, @port = 161)
    @socket = build_socket
    @connected = false
  end

  # Close the underlying UDP socket. The next request reconnects transparently.
  # A `Client` is not safe for concurrent use — use one per fiber.
  def close : Nil
    reset_socket
  end

  # A fresh, buffered UDP socket with the configured read timeout.
  private def build_socket : UDPSocket
    socket = UDPSocket.new
    socket.sync = false
    socket.read_timeout = timeout.seconds
    socket
  end

  # True when *oid* is the *base* subtree or a descendant of it. Compares OID
  # arcs, not the raw string, so a sibling column (e.g. `.10`) that merely shares
  # a string prefix with `.1` is not treated as a child.
  def self.oid_within?(oid : String, base : String) : Bool
    oid == base || oid.starts_with?("#{base}.")
  end

  private def with_socket(&)
    sock = connected_socket
    begin
      yield sock
    rescue ex : IO::TimeoutError
      reset_socket
      raise SNMP::TimeoutError.new("no response from #{host}:#{port} within #{timeout}s", cause: ex)
    rescue ex : BinData::ParseError
      reset_socket
      raise SNMP::ParseError.new("failed to decode SNMP response from #{host}:#{port}: #{ex.message}", cause: ex)
    end
  end

  # The persistent socket, connected on first use and reused across requests
  # (avoids a connect+close and a new source port on every call).
  private def connected_socket : UDPSocket
    if socket.closed?
      @socket = build_socket
      @connected = false
    end
    unless @connected
      socket.connect(host, port)
      @connected = true
    end
    socket
  end

  private def reset_socket : Nil
    socket.close unless socket.closed?
    @connected = false
  end

  def get(oid : String) : SNMP::Message
    with_socket { |sock| get(oid, sock) }
  end

  # Multi-varbind Get: one round-trip binding every OID; the Response carries a
  # varbind per requested OID.
  def get(oids : Enumerable(String)) : SNMP::Message
    with_socket { |sock| get(oids, sock) }
  end

  private def get(oid : String, sock : UDPSocket) : SNMP::Message
    request(sock) { session.get(oid) }
  end

  private def get(oids : Enumerable(String), sock : UDPSocket) : SNMP::Message
    request(sock) { session.get(oids) }
  end

  def get_next(oid : String) : SNMP::Message
    with_socket { |sock| get_next(oid, sock) }
  end

  # Multi-varbind GetNext: advances every supplied OID in one round-trip.
  def get_next(oids : Enumerable(String)) : SNMP::Message
    with_socket { |sock| get_next(oids, sock) }
  end

  private def get_next(oid : String, sock : UDPSocket) : SNMP::Message
    request(sock) { session.get_next(oid) }
  end

  private def get_next(oids : Enumerable(String), sock : UDPSocket) : SNMP::Message
    request(sock) { session.get_next(oids) }
  end

  # GetBulk: one round-trip returning up to *max_repetitions* successors per
  # repeating OID. Returns the raw Response message (its PDU holds every varbind).
  def get_bulk(oids : Enumerable(String), non_repeaters = 0, max_repetitions = 10) : SNMP::Message
    with_socket { |sock| get_bulk(oids, sock, non_repeaters, max_repetitions) }
  end

  private def get_bulk(oids : Enumerable(String), sock : UDPSocket, non_repeaters, max_repetitions) : SNMP::Message
    request(sock) { session.get_bulk(oids, non_repeaters, max_repetitions) }
  end

  # Set a single OID to *value* (a typed SNMP value, a Crystal primitive, or a
  # raw `ASN1::BER`) and return the agent's Response.
  def set(oid : String, value) : SNMP::Message
    with_socket { |sock| set(oid, value, sock) }
  end

  # Multi-varbind Set: assign every OID => value pair in one round-trip.
  def set(values : Hash(String, _)) : SNMP::Message
    with_socket { |sock| set(values, sock) }
  end

  private def set(oid : String, value, sock : UDPSocket) : SNMP::Message
    request(sock) { session.set(oid, value) }
  end

  private def set(values : Hash(String, _), sock : UDPSocket) : SNMP::Message
    request(sock) { session.set(values) }
  end

  # Send an SNMPv2-Trap to the configured host/port (typically a trap sink on
  # 162). Fire-and-forget: a trap is unacknowledged, so nothing is read back.
  def send_trap_v2(oid : String, uptime = 0, varbinds : Array(SNMP::VarBind) = [] of SNMP::VarBind) : Nil
    emit community_session.trap_v2(oid, uptime, varbinds)
  end

  # Send an SNMPv1 Trap (RFC 1157). Fire-and-forget.
  def send_trap_v1(enterprise : String, agent_address : String, generic_trap : SNMP::GenericTrap, specific_trap = 0, uptime = 0, varbinds : Array(SNMP::VarBind) = [] of SNMP::VarBind) : Nil
    emit community_session.trap_v1(enterprise, agent_address, generic_trap, specific_trap, uptime, varbinds)
  end

  # Send an Inform and return the receiver's acknowledging Response.
  def send_inform(oid : String, uptime = 0, varbinds : Array(SNMP::VarBind) = [] of SNMP::VarBind) : SNMP::Message
    message = community_session.inform(oid, uptime, varbinds)
    with_socket { |sock| transceive(sock, message) }
  end

  # Notifications use the community (v1/v2c) session; v3 notification sending is
  # not implemented yet.
  private def community_session : SNMP::Session
    sess = session
    raise Error.new("notification sending requires a v1/v2c (community) session") unless sess.is_a?(SNMP::Session)
    sess
  end

  private def emit(message : SNMP::Message) : Nil
    with_socket(&.send(message.to_ber.to_slice))
  end

  # Collect a subtree into an array. NOTE: this buffers every message in memory;
  # for large subtrees prefer the block form below or `#bulk_walk`, which stream.
  def walk(oid : String) : Array(SNMP::Message)
    messages = [] of SNMP::Message
    walk(oid) { |msg| messages << msg }
    messages
  end

  def walk(oid : String, &)
    with_socket do |sock|
      current = oid
      loop do
        msg = get_next(current, sock)
        varbind = msg.varbinds.first?
        break unless varbind && self.class.oid_within?(varbind.oid, oid)
        break if varbind.end_of_mib_view?

        check_walk_progress(current, varbind.oid)
        current = varbind.oid
        yield msg
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

        varbinds.each do |varbind|
          # End of the MIB, or the subtree is exhausted (GetBulk overshoots it).
          return self if varbind.end_of_mib_view? || !self.class.oid_within?(varbind.oid, oid)

          check_walk_progress(current, varbind.oid)
          current = varbind.oid
          yield varbind
        end
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

  private def check_walk_progress(previous : String, current : String) : Nil
    previous_arcs = previous.split('.').map { |arc| BigInt.new(arc) }
    current_arcs = current.split('.').map { |arc| BigInt.new(arc) }
    if current_arcs <= previous_arcs
      raise Error.new("agent returned non-increasing OID #{current} after #{previous}")
    end
  end

  protected def check_validation_probe(sock)
    if session.must_revalidate?
      probe = session.engine_validation_probe
      sock.send(probe.to_ber.to_slice)
      response = receive_response(sock, probe) { |ber| session.parse(ber, nil) }
      session.validate(response.as(V3::Message))
    end
  end

  # Build a fresh request, send it, and return the parsed response — transparently
  # recovering from a recoverable v3 usmStats Report (notInTimeWindow /
  # unknownEngineID) by resyncing the engine params and retrying exactly once.
  # A non-recoverable Report, or a Report that survives the retry, raises
  # `Security::ReportError`. The block is re-invoked on retry so the rebuilt
  # request carries the freshly synced engine boots/time/id.
  private def request(sock, &build : -> SNMP::Message) : SNMP::Message
    check_validation_probe(sock)
    response = transceive(sock, build.call)

    sess = session
    if response.is_a?(SNMP::V3::Message) && response.report? && sess.is_a?(SNMP::V3::Session)
      stat = response.usm_stat
      if stat.try(&.resyncable?)
        sess.resync_from(response)
        response = transceive(sock, build.call)
      end

      if response.is_a?(SNMP::V3::Message) && response.report?
        raise SNMP::V3::Security::ReportError.new(
          "agent returned a usmStats Report (#{response.usm_stat || "unknown"})", response.usm_stat)
      end
    end

    response
  end

  private def transceive(sock, message : SNMP::Message) : SNMP::Message
    payload = message.is_a?(SNMP::V3::Message) ? session.prepare(message) : message.to_ber
    sock.send(payload.to_slice)
    receive_response(sock, message) { |ber| session.parse(ber) }
  end

  private def receive_response(sock : UDPSocket, request : SNMP::Message, &) : SNMP::Message
    read_timeout = sock.read_timeout
    deadline = Time.instant + read_timeout if read_timeout

    loop do
      ber = read_datagram(sock)
      # Match before parsing so a stale v3 message cannot affect session timeliness.
      if !request.is_a?(V3::Message) || matching_message_id?(ber, request)
        response = yield ber
        # Reports correlate by msgID. Their scoped request-id can be zero.
        return response if response.is_a?(V3::Message) && response.report?
        return response if matching_response?(response, request)
      end

      if deadline
        remaining = deadline - Time.instant
        raise IO::TimeoutError.new("Read timed out") if remaining <= Time::Span.zero
        sock.read_timeout = remaining
      end
    end
  ensure
    sock.read_timeout = read_timeout
  end

  private def matching_message_id?(ber : ASN1::BER, request : V3::Message) : Bool
    fields = SNMP.ber_fields(ber, 2, "SNMP message")
    return true unless fields[0].get_integer == Version::V3.value

    header = SNMP.ber_fields(fields[1], 1, "v3 header")
    header[0].get_integer == request.id
  end

  private def matching_response?(response : SNMP::Message, request : SNMP::Message) : Bool
    return false unless response.request.response? && response.request_id == request.request_id
    return false unless response.version == request.version

    request.is_a?(V3::Message) || response.community == request.community
  end

  private def read_datagram(sock : UDPSocket) : ASN1::BER
    buffer = @receive_buffer ||= Bytes.new(MAX_DATAGRAM_SIZE)
    size, _ = sock.receive(buffer)
    io = IO::Memory.new(buffer[0, size], false)
    ber = ASN1::BER.new
    ber.max_content_length = size
    ber.read(io)
    raise SNMP::ParseError.new("unexpected trailing bytes in SNMP response") unless io.pos == io.size
    ber
  rescue ex : ASN1::Error | IO::EOFError
    raise SNMP::ParseError.new("failed to decode SNMP response from #{host}:#{port}: #{ex.message}", cause: ex)
  end
end
