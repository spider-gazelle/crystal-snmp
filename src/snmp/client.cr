require "socket"
require "../snmp"

class SNMP::Client
  class Error < Exception
  end

  getter socket : UDPSocket
  getter session : SNMP::Session
  getter host, timeout, port

  def initialize(@host : String, community = "public", @timeout = 3, @port = 161)
    @socket = UDPSocket.new
    socket.sync = false
    socket.read_timeout = timeout
    @session = SNMP::Session.new(community: community)
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
    sock.write_bytes session.get(oid)
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
    sock.write_bytes session.get_next(oid)
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
end
