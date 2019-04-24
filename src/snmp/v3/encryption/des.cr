require "openssl/cipher"

# Based on: https://github.com/swisscom/ruby-netsnmp/blob/master/lib/netsnmp/encryption/aes.rb

module SNMP::Encryption
  class DES
    def initialize(@priv_key : String, @local = 0)
    end

    def encrypt(decrypted_data : Bytes, engine_boots, engine_time = nil)
      cipher = OpenSSL::Cipher.new("des-cbc")

      iv, salt = generate_encryption_key(engine_boots)

      cipher.encrypt
      cipher.iv = iv
      cipher.key = des_key

      if (diff = decrypted_data.bytesize % 8) != 0
        io = IO::Memory.new
        io << decrypted_data
        # Pad with 0's
        (0...(8 - diff)).each do
          io << 0u8
        end
        decrypted_data = io.to_slice
      end

      encrypted_data = IO::Memory.new
      encrypted_data.write(cipher.update(decrypted_data))
      encrypted_data.write(cipher.final)
      {encrypted_data.to_slice, salt}
    end

    def decrypt(encrypted_data : Bytes, salt : Bytes, engine_boots = nil, engine_time = nil)
      raise "invalid priv salt received" unless (salt.size % 8).zero?
      raise "invalid encrypted PDU received" unless (encrypted_data.size % 8).zero?

      cipher = OpenSSL::Cipher.new("des-cbc")
      cipher.padding = 0

      iv = generate_decryption_key(salt)

      cipher.decrypt
      cipher.key = des_key
      cipher.iv = iv

      decrypted_data = IO::Memory.new
      decrypted_data.write cipher.update(encrypted_data)
      decrypted_data.write cipher.final
      decrypted_data.rewind

      # Don't think we need to remove the padding
      # hlen, bodylen = OpenSSL::ASN1.traverse(decrypted_data) { |_, _, x, y, *| break x, y }
      # decrypted_data.byteslice(0, hlen + bodylen)

      # Return as an IO so we can read out the BER directly
      decrypted_data
    end

    # 8.1.1.1
    private def generate_encryption_key(boots)
      io = IO::Memory.new
      io << 0xffu8 & (boots >> 24)
      io << 0xffu8 & (boots >> 16)
      io << 0xffu8 & (boots >> 8)
      io << 0xffu8 & boots
      io << 0xffu8 & (@local >> 24)
      io << 0xffu8 & (@local >> 16)
      io << 0xffu8 & (@local >> 8)
      io << 0xffu8 & @local
      salt = io.to_slice

      @local = @local == 0xffffffff ? 0 : @local + 1

      iv = generate_decryption_key(salt)
      {iv, salt}
    end

    private def generate_decryption_key(salt : Bytes)
      iv = @priv_key[8, 8].to_slice
      iv.each_with_index do |byte, index|
        iv[index] = byte ^ salt[index]
      end
      iv
    end

    private def des_key
      @priv_key[0, 8]
    end
  end
end
