require "openssl"

# Based on: https://github.com/swisscom/ruby-netsnmp/blob/master/lib/netsnmp/security_parameters.rb

class SNMP::V3::Security
  IPAD = Bytes.new(64, 0x36)
  OPAD = Bytes.new(64, 0x5c)

  class Error < Exception
  end

  enum AuthProtocol
    MD5
    SHA
  end

  enum PrivacyProtocol
    DES
    AES
  end

  property engine_id : String
  getter username : String
  getter security_level : MessageFlags
  getter auth_protocol : AuthProtocol
  getter priv_protocol : PrivacyProtocol
  getter verify_messages : Bool
  @auth_pass_key : Bytes = Bytes.new(0)
  @priv_pass_key : Bytes = Bytes.new(0)
  @digest : OpenSSL::Digest

  def initialize(
    @username,
    @engine_id = "",
    @auth_protocol = AuthProtocol::MD5,
    @auth_password = "",
    @priv_protocol = PrivacyProtocol::DES,
    @priv_password = "",
    @verify_messages = true
  )
    @security_level = if !@priv_password.empty?
                        MessageFlags::Authentication | MessageFlags::Privacy
                      elsif !@auth_password.empty?
                        MessageFlags::Authentication
                      else
                        MessageFlags::None
                      end

    @digest = case @auth_protocol
              when AuthProtocol::MD5
                OpenSSL::Digest.new("md5")
              when AuthProtocol::SHA
                OpenSSL::Digest.new("sha1")
              else
                raise ArgumentError.new("unsupported digest protocol")
              end

    if @security_level > MessageFlags::None
      raise ArgumentError.new("auth password must have between 8 to 32 characters") unless (8..32).covers?(@auth_password.size)
      @auth_pass_key = passkey(@auth_password)
    end

    if @security_level == (MessageFlags::Authentication | MessageFlags::Privacy)
      raise ArgumentError.new("priv password must have between 8 to 32 characters") unless (8..32).covers?(@priv_password.size)
      @priv_pass_key = passkey(@priv_password)
    end
  end

  # The default message security model
  def security_model : SecurityModel
    if @security_level == MessageFlags::Privacy
      SecurityModel::User
    else
      SecurityModel::Transport
    end
  end

  def encode(pdu : ASN1::BER, engine_time, engine_boots)
    if @security_level.privacy?
      crypt = encryption
      io = IO::Memory.new
      io.write_bytes pdu

      encrypted_pdu, salt = crypt.encrypt(io.to_slice, engine_boots: engine_boots, engine_time: engine_time)

      # WTF: This does not match when using DES... Always out by 1 byte
      # slice = io.to_slice
      # crypt.decrypt(encrypted_pdu, salt, engine_boots, engine_time).to_slice[0...slice.size].should eq slice

      pdu = ASN1::BER.new.set_bytes(encrypted_pdu)
      {pdu, salt.to_slice}
    else
      {pdu, Bytes.new(0)}
    end
  end

  def decode(pdu : ASN1::BER, salt : Bytes, engine_time, engine_boots)
    if @security_level.privacy? && pdu.tag == UniversalTags::OctetString
      crypt = encryption
      encrypted_pdu = pdu.get_bytes
      pdu_der = crypt.decrypt(encrypted_pdu, salt, engine_boots, engine_time)

      pdu_der.read_bytes(ASN1::BER)
    else
      pdu
    end
  end

  def sign(message : ASN1::BER)
    # don't sign unless you have to
    return Bytes.new(0) if @security_level == MessageFlags::None

    io = IO::Memory.new
    io.write auth_key
    io.write Bytes.new(@auth_protocol == AuthProtocol::MD5 ? 48 : 44)
    bytes = io.to_slice

    k1 = bytes.clone
    k1.each_with_index do |byte, index|
      k1[index] = byte ^ IPAD[index]
    end

    k2 = bytes
    k2.each_with_index do |byte, index|
      k2[index] = byte ^ OPAD[index]
    end

    io = IO::Memory.new
    io.write k1
    io.write_bytes message

    @digest.reset
    @digest << io.to_slice
    d1 = @digest.final

    io = IO::Memory.new
    io.write k2
    io.write d1

    @digest.reset
    @digest << io.to_slice
    @digest.final[0, 12]
  end

  @auth_key : Bytes = Bytes.new(0)

  def auth_key
    @auth_key = localize_key(@auth_pass_key) if @auth_key.empty?
    @auth_key
  end

  @priv_key : Bytes = Bytes.new(0)

  def priv_key
    @priv_key = localize_key(@priv_pass_key) if @priv_key.empty?
    @priv_key
  end

  private def localize_key(key)
    @digest.reset
    @digest << key
    @digest << @engine_id.hexbytes
    @digest << key

    @digest.final
  end

  def passkey(password)
    @digest.reset
    password_index = 0

    password_length = password.size
    while password_index < 1048576
      initial = password_index % password_length
      rotated = password[initial..-1] + password[0, initial]
      buffer = rotated * (64 // rotated.size) + rotated[0, 64 % rotated.size]
      password_index += 64
      @digest << buffer
    end

    dig = @digest.final
    dig = dig[0, 16] if @auth_protocol == AuthProtocol::MD5
    dig
  end

  @encryption : (AES | DES)?

  private def encryption : AES | DES
    crypt = @encryption
    crypt ||= case @priv_protocol
              when PrivacyProtocol::DES
                DES.new(priv_key)
              when PrivacyProtocol::AES
                AES.new(priv_key)
              else
                raise Security::Error.new("unknown privacy protocol")
              end
    @encryption = crypt
  end
end

require "./security/*"
