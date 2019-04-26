require "openssl"

# Based on: https://github.com/swisscom/ruby-netsnmp/blob/master/lib/netsnmp/security_parameters.rb

class SNMP::V3::Security
  IPAD = Bytes.new(64, 0x36)
  OPAD = Bytes.new(64, 0x5c)

  # Timeliness is part of SNMP V3 Security
  # The topic is described very nice here https://www.snmpsharpnet.com/?page_id=28
  # https://www.ietf.org/rfc/rfc2574.txt 1.4.1 Timeliness
  # The probe is outdated after 150 seconds which results in a PDU Error, therefore it should expire before that and be renewed
  # The 150 Seconds is specified in https://www.ietf.org/rfc/rfc2574.txt 2.2.3
  TIMELINESS_THRESHOLD = 150

  enum SecLevel
    NoAuth
    AuthNoPriv
    AuthWithPriv = 3
  end

  enum AuthProtocol
    MD5
    SHA
  end

  enum PrivacyProtocol
    DES
    AES
  end

  getter username : String
  getter engine_id : Bytes
  getter security_level : SecLevel
  getter auth_protocol : AuthProtocol
  getter priv_protocol : PrivacyProtocol
  property timeliness : Int64 = 0_i64
  @auth_pass_key : Bytes = Bytes.new(0)
  @priv_pass_key : Bytes = Bytes.new(0)
  @digest : OpenSSL::Digest

  def initialize(
    @username,
    @engine_id = Bytes.new(0),
    @auth_protocol = AuthProtocol::MD5,
    @auth_password = "",
    @priv_protocol = PrivacyProtocol::DES,
    @priv_password = ""
  )
    @security_level = if !@priv_password.empty?
                        SecLevel::AuthWithPriv
                      elsif !@auth_password.empty?
                        SecLevel::AuthNoPriv
                      else
                        SecLevel::NoAuth
                      end

    @digest = case @auth_protocol
              when AuthProtocol::MD5
                OpenSSL::Digest.new("md5")
              when AuthProtocol::SHA
                OpenSSL::Digest.new("sha1")
              else
                raise "unsupported digest protocol"
              end

    if @security_level > SecLevel::NoAuth
      raise "auth password must have between 8 to 32 characters" unless (8..32).covers?(@auth_password.size)
      @auth_pass_key = passkey(@auth_password)
    end

    if @security_level == SecLevel::AuthWithPriv
      raise "priv password must have between 8 to 32 characters" unless (8..32).covers?(@priv_password.size)
      @priv_pass_key = passkey(@priv_password)
    end
  end

  def engine_id=(id)
    @timeliness = Time.monotonic.to_i
    @engine_id = id
  end

  def encode(pdu : ASN1::BER, salt : ASN1::BER, engine_time, engine_boots)
    if crypt = encryption
      io = IO::Memory.new
      io.write_bytes pdu

      encrypted_pdu, salt = crypt.encrypt(io.to_slice, engine_boots: engine_boots, engine_time: engine_time)
      pdu = ASN1::BER.new.set_string(encrypted_pdu, UniversalTags::OctetString)
      salt = ASN1::BER.new.set_string(salt, UniversalTags::OctetString)

      {pdu, salt}
    else
      {pdu, salt}
    end
  end

  def decode(der : ASN1::BER, salt : ASN1::BER, engine_time, engine_boots)
    if crypt = encryption
      encrypted_pdu = der.get_bytes
      pdu_der = crypt.decrypt(encrypted_pdu, salt: salt.get_bytes, engine_time: engine_time, engine_boots: engine_boots)
      pdu_der.read_bytes(ASN1::BER)
    else
      der
    end
  end

  def sign(message)
    # don't sign unless you have to
    return nil if @security_level == SecLevel::NoAuth

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
    io.write message

    digest.reset
    digest << io.to_slice
    d1 = digest.digest

    io = IO::Memory.new
    io.write k2
    io.write d1

    digest.reset
    digest << io.to_slice
    digest.digest[0, 12]
  end

  def verify(stream, salt)
    return if @security_level == SecLevel::NoAuth
    verisalt = sign(stream)
    raise "invalid message authentication salt" unless verisalt == salt
  end

  def must_revalidate?
    return @engine_id.empty? unless authorizable?
    return true if @engine_id.empty? || @timeliness.nil?
    (Time.monotonic.to_i - @timeliness) >= TIMELINESS_THRESHOLD
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
    @digest << @engine_id
    @digest << key

    @digest.digest
  end

  def passkey(password)
    @digest.reset
    password_index = 0

    password_length = password.size
    while password_index < 1048576
      initial = password_index % password_length
      rotated = password[initial..-1] + password[0, initial]
      buffer = rotated * (64 / rotated.size) + rotated[0, 64 % rotated.size]
      password_index += 64
      @digest << buffer
    end

    dig = @digest.digest
    dig = dig[0, 16] if @auth_protocol == AuthProtocol::MD5
    dig
  end

  private def encryption
    @encryption ||= case @priv_protocol
                    when PrivacyProtocol::DES
                      Encryption::DES.new(priv_key)
                    when PrivacyProtocol::AES
                      Encryption::AES.new(priv_key)
                    end
  end

  private def authorizable?
    @security_level > SecLevel::NoAuth
  end
end

require "./security/*"
