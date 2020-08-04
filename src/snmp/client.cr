require "socket"
require "../snmp"

class SNMP::Client
  class Error < Exception
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

  private def with_socket
    if socket.closed?
      @socket = UDPSocket.new
      socket.sync = false
      socket.read_timeout = timeout
    end
    socket.connect(host, port)
    yield socket
    socket.close
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
      while (!msg.nil? && msg.oid.includes?(oid))
        # Break at END OF MIB
        break if msg.value.payload.empty?

        messages << msg
        msg = get_next(msg.oid, sock)
      end
    end
    messages
  end

  def walk(oid : String)
    with_socket do |sock|
      msg = get_next(oid, sock)

      # While the message is not nil and the returned oid is a child of the request
      while (!msg.nil? && msg.oid.includes?(oid))
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
