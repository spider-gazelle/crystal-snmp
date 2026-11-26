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

  # Fixed keys and signatures computed independently with Python hashlib and hmac.
  {
    {AuthProtocol::SHA224, "f6a87cc451c644a1ef2bb93dbe7c7065df030655b79132780073bd29",
     "68815012c7bb5fc5050b068e960c96a0"},
    {AuthProtocol::SHA384, "4b666b2279769119a18edc2a20816ba235c0d1e7630382794dd25e56776b549d24570c08c1706c5025aa4b24b35958c7",
     "a4a73aa8271c8bae586e11dbcfb24a5015a04be0be5a5dd018e80abcb17ae43f"},
  }.each do |auth, localized_key, hmac|
    it "matches the #{auth} key-localization and truncated HMAC vectors" do
      sec = SNMP::V3::Security.new("user", engine_id, auth, auth_password: "maplesyrup")
      message = ASN1::BER.new.set_bytes("snmp auth vector".to_slice)

      sec.auth_key.hexstring.should eq(localized_key)
      sec.sign(message).hexstring.should eq(hmac)
    end
  end

  it "round-trips an AES-256 encrypted PDU" do
    sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA256, auth_password: "maplesyrup", priv_protocol: PrivacyProtocol::AES256, priv_password: "maplesyrup")
    sec.priv_key.size.should eq(32)

    pdu = ASN1::BER.new.set_string("secret payload here", tag: ASN1::BER::UniversalTags::OctetString)
    encrypted, salt = sec.encode(pdu, 100, 1)
    sec.decode(encrypted, salt, 100, 1).get_string.should eq("secret payload here")
  end

  # A scoped Get PDU encrypted independently with openssl enc and a fixed USM IV.
  {
    {PrivacyProtocol::AES192, "f70ccca5dd8604fd02660f8d3a56acf5fd365040d31e22c3",
     "9dceb1d7a04cde2e4e25a40b8b898c4f8cc236d7bc84003ebaeb51c6425aae5f3b1c800e75b5ef70afe2e956"},
    {PrivacyProtocol::AES256, "f70ccca5dd8604fd02660f8d3a56acf5fd365040d31e22c3fc7d7d2a28f38f34",
     "7b88e2913f338f6f4691b077ce605c9f208a7ac74151221e7f0551a82513bfb8d053b0afee5211c0805622e1"},
  }.each do |privacy, extended_key, ciphertext|
    it "matches the #{privacy} key-extension and scoped PDU encryption vectors" do
      sec = SNMP::V3::Security.new("user", engine_id, AuthProtocol::SHA, auth_password: "maplesyrup",
        priv_protocol: privacy, priv_password: "maplesyrup")
      scoped_pdu = "302a040b80000000010203040506070400a01902012a020100020100300e300c06082b060102010105000500".hexbytes
      sec.priv_key.hexstring.should eq(extended_key)

      aes = SNMP::V3::Security::AES.new(sec.priv_key, 0x0102030405060708_u64)
      encrypted, salt = aes.encrypt(scoped_pdu, engine_boots: 3, engine_time: 150)
      salt.hexstring.should eq("0102030405060708")
      encrypted.hexstring.should eq(ciphertext)

      peer_message = ASN1::BER.new.set_bytes(ciphertext.hexbytes)
      sec.decode(peer_message, salt, 150, 3).to_slice.should eq(scoped_pdu)
    end
  end

  {"usr-sha224-aes" => AuthProtocol::SHA224, "usr-sha384-aes" => AuthProtocol::SHA384}.each do |username, auth|
    it "interoperates with Net-SNMP using #{auth} authentication and AES", tags: "e2e" do
      session = SNMP::V3::Session.new(username, "authkey1", "privkey1",
        auth_protocol: auth, priv_protocol: PrivacyProtocol::AES)
      client = SNMP::Client.new(TEST_SNMP_SERVER, session, port: TEST_SNMP_PORT)
      response = client.get("1.3.6.1.2.1.1.4.0").as(SNMP::V3::Message)

      response.flags.authentication?.should be_true
      response.flags.privacy?.should be_true
      response.value.get_string.should eq("SNMP Laboratories, info@snmplabs.com")
    ensure
      client.try(&.close)
    end
  end
end
