class SNMP
  def self.get_unsigned64(ber : ASN1::BER) : UInt64
    io = IO::Memory.new(8)
    bytes = ber.payload
    io.pos = 8 - bytes.size
    io.write(bytes)
    io.rewind
    io.read_bytes(UInt64, IO::ByteFormat::BigEndian)
  end

  def self.set_unsigned64(ber : ASN1::BER, value : UInt64)
    io = IO::Memory.new(8)
    io.write_bytes(value, IO::ByteFormat::BigEndian)
    bytes = io.to_slice

    index = 0
    bytes.each do |byte|
      break if byte > 0
      index += 1
    end

    ber.payload = bytes[index, 8 - index]
  end

  def self.get_unsigned32(ber : ASN1::BER) : UInt32
    io = IO::Memory.new(4)
    bytes = ber.payload
    io.pos = 4 - bytes.size
    io.write(bytes)
    io.rewind
    io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
  end

  def self.set_unsigned32(ber : ASN1::BER, value : UInt32)
    io = IO::Memory.new(4)
    io.write_bytes(value, IO::ByteFormat::BigEndian)
    bytes = io.to_slice

    index = 0
    bytes.each do |byte|
      break if byte > 0
      index += 1
    end

    ber.payload = bytes[index, 4 - index]
  end
end
