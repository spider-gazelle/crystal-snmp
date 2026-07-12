require "openssl"
require "openssl/hmac"

# Based on: https://github.com/swisscom/ruby-netsnmp/blob/master/lib/netsnmp/security_parameters.rb

class SNMP::V3::Security
  class Error < SNMP::Error
  end

  # Raised when a message's authentication signature does not verify.
  class AuthenticationError < Error
  end

  # Raised when an inbound authenticated message falls outside the RFC 3414
  # time window — a replay, or a boots/clock mismatch with the remote engine.
  class NotInTimeWindowError < AuthenticationError
  end

  # Raised when the agent returns a usmStats Report PDU that cannot be recovered
  # by a resync/retry (e.g. wrongDigest, unknownUserName), or when a resyncable
  # Report is still returned after the retry.
  class ReportError < Error
    getter usm_stat : V3::UsmStat?

    def initialize(message, @usm_stat = nil)
      super(message)
    end
  end

  enum AuthProtocol
    MD5
    SHA # SHA-1
    SHA224
    SHA256
    SHA384
    SHA512
  end

  enum PrivacyProtocol
    DES
    AES # AES-128
    AES192
    AES256
  end

  property engine_id : String
  getter username : String
  getter security_level : MessageFlags
  getter auth_protocol : AuthProtocol
  getter priv_protocol : PrivacyProtocol

  # Whether inbound authenticated messages have their HMAC verified.
  #
  # WARNING: setting this to `false` disables authentication verification of
  # received messages — a forged or tampered response is then accepted as
  # genuine. Leave it at the default (`true`) unless you are deliberately
  # inspecting traffic and understand that the security guarantee is voided.
  getter? verify_messages : Bool
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
    @verify_messages = true,
  )
    @security_level = if !@priv_password.empty?
                        MessageFlags::Authentication | MessageFlags::Privacy
                      elsif !@auth_password.empty?
                        MessageFlags::Authentication
                      else
                        MessageFlags::None
                      end

    @digest = OpenSSL::Digest.new(digest_name)

    if @security_level > MessageFlags::None
      raise ArgumentError.new("auth password must have between 8 to 32 characters") unless (8..32).covers?(@auth_password.size)
      @auth_pass_key = passkey(@auth_password)
    end

    if @security_level == (MessageFlags::Authentication | MessageFlags::Privacy)
      raise ArgumentError.new("priv password must have between 8 to 32 characters") unless (8..32).covers?(@priv_password.size)
      @priv_pass_key = passkey(@priv_password)
    end
  end

  # This class implements the User-based Security Model.
  def security_model : SecurityModel
    SecurityModel::USM
  end

  def encode(pdu : ASN1::BER, engine_time, engine_boots)
    if @security_level.privacy?
      crypt = encryption
      io = IO::Memory.new
      io.write_bytes pdu

      encrypted_pdu, salt = crypt.encrypt(io.to_slice, engine_boots: engine_boots, engine_time: engine_time)

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
    io.write_bytes message
    # HMAC(auth_key, message) truncated to the protocol's msgAuthenticationParameters length
    OpenSSL::HMAC.digest(hmac_algorithm, auth_key, io.to_slice)[0, auth_param_length]
  end

  # OpenSSL digest name for the auth protocol.
  private def digest_name : String
    case @auth_protocol
    in AuthProtocol::MD5    then "md5"
    in AuthProtocol::SHA    then "sha1"
    in AuthProtocol::SHA224 then "sha224"
    in AuthProtocol::SHA256 then "sha256"
    in AuthProtocol::SHA384 then "sha384"
    in AuthProtocol::SHA512 then "sha512"
    end
  end

  private def hmac_algorithm : OpenSSL::Algorithm
    case @auth_protocol
    in AuthProtocol::MD5    then OpenSSL::Algorithm::MD5
    in AuthProtocol::SHA    then OpenSSL::Algorithm::SHA1
    in AuthProtocol::SHA224 then OpenSSL::Algorithm::SHA224
    in AuthProtocol::SHA256 then OpenSSL::Algorithm::SHA256
    in AuthProtocol::SHA384 then OpenSSL::Algorithm::SHA384
    in AuthProtocol::SHA512 then OpenSSL::Algorithm::SHA512
    end
  end

  # msgAuthenticationParameters length: RFC 3414 (MD5/SHA1 = 12) and RFC 7860.
  def auth_param_length : Int32
    case @auth_protocol
    in AuthProtocol::MD5    then 12
    in AuthProtocol::SHA    then 12
    in AuthProtocol::SHA224 then 16
    in AuthProtocol::SHA256 then 24
    in AuthProtocol::SHA384 then 32
    in AuthProtocol::SHA512 then 48
    end
  end

  @auth_key : Bytes = Bytes.new(0)

  def auth_key
    @auth_key = localize_key(@auth_pass_key) if @auth_key.empty?
    @auth_key
  end

  @priv_key : Bytes = Bytes.new(0)

  def priv_key
    if @priv_key.empty?
      key = localize_key(@priv_pass_key)
      needed = priv_key_length
      # extend a too-short localized key; never truncate (priv_key is the full key material)
      @priv_key = key.size < needed ? extend_key(key, needed) : key
    end
    @priv_key
  end

  # Localized key length required by the privacy protocol.
  private def priv_key_length : Int32
    case @priv_protocol
    in PrivacyProtocol::DES    then 16 # 8-byte key + 8-byte pre-IV
    in PrivacyProtocol::AES    then 16
    in PrivacyProtocol::AES192 then 24
    in PrivacyProtocol::AES256 then 32
    end
  end

  # Blumenthal key-localization extension (draft-blumenthal-aes-usm-04 3.1.2.1):
  # Kul' = Kul || H(Kul) || H(Kul || H(Kul)) || ... — each step hashes the whole
  # accumulated key. (Cisco uses the alternative Reeder 3DESEDE chaining.)
  private def extend_key(key : Bytes, needed : Int32) : Bytes
    io = IO::Memory.new
    io.write key
    while io.size < needed
      @digest.reset
      @digest << io.to_slice
      io.write @digest.final
    end
    io.to_slice[0, needed]
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
              else # AES-128/192/256 — pass exactly the cipher key length
                AES.new(priv_key[0, priv_key_length])
              end
    @encryption = crypt
  end
end

require "./security/*"
