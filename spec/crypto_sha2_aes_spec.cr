require "./helper"

alias AuthProtocol = SNMP::V3::Security::AuthProtocol
alias PrivacyProtocol = SNMP::V3::Security::PrivacyProtocol

# usmHMAC-SHA-2 (RFC 7860) auth + AES-192/256 privacy (Blumenthal key extension).
# AES is in the default OpenSSL provider, so these run without the legacy provider.
describe "SNMP::V3::Security SHA-2 / AES-192-256" do
  engine_id = "8000000001020304050607"

  it "signs with SHA-256, truncated to 24 bytes, matching OpenSSL::HMAC" do
    sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA256, auth_password: "maplesyrup")
    msg = ASN1::BER.new.set_string("scoped pdu placeholder bytes", tag: ASN1::BER::UniversalTags::OctetString)
    io = IO::Memory.new
    io.write_bytes(msg)
    expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, sec.auth_key, io.to_slice)[0, 24]

    sec.sign(msg).should eq(expected)
    sec.sign(msg).size.should eq(24)
  end

  it "signs with SHA-512, truncated to 48 bytes (128-byte HMAC block)" do
    sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA512, auth_password: "maplesyrup")
    msg = ASN1::BER.new.set_string("scoped pdu placeholder bytes", tag: ASN1::BER::UniversalTags::OctetString)
    io = IO::Memory.new
    io.write_bytes(msg)
    expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA512, sec.auth_key, io.to_slice)[0, 48]

    sec.sign(msg).should eq(expected)
    sec.sign(msg).size.should eq(48)
  end

  it "round-trips an AES-256 encrypted PDU" do
    sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA256, auth_password: "maplesyrup", priv_protocol: PrivacyProtocol::AES256, priv_password: "maplesyrup")
    sec.priv_key.size.should eq(32)

    pdu = ASN1::BER.new.set_string("secret payload here", tag: ASN1::BER::UniversalTags::OctetString)
    encrypted, salt = sec.encode(pdu, 100, 1)
    sec.decode(encrypted, salt, 100, 1).get_string.should eq("secret payload here")
  end

  it "extends a short localized key for AES-192 (SHA-1 auth -> 24 bytes)" do
    sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA, auth_password: "maplesyrup", priv_protocol: PrivacyProtocol::AES192, priv_password: "maplesyrup")
    sec.priv_key.size.should eq(24)

    pdu = ASN1::BER.new.set_string("payload", tag: ASN1::BER::UniversalTags::OctetString)
    encrypted, salt = sec.encode(pdu, 100, 1)
    sec.decode(encrypted, salt, 100, 1).get_string.should eq("payload")
  end
end
