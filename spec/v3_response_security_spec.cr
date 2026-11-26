require "./helper"

private def v3_response(session : SNMP::V3::Session, security_model = session.security.security_model)
  response = session.set("1.3.6.1.2.1.1.5.0", "hostname")
  response.request = SNMP::Request::Response
  response.security_model = security_model
  response.flags = session.security.security_level
  session.prepare(response)
end

describe SNMP::V3::Session do
  engine_id = "8000000001020304"

  {
    {"noAuthNoPriv", "", ""},
    {"authNoPriv", "authkey1", ""},
    {"authPriv", "authkey1", "privkey1"},
  }.each do |level, auth_password, priv_password|
    it "accepts a response matching the session's #{level} settings" do
      session = SNMP::V3::Session.new("user", auth_password, priv_password, engine_id,
        priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES)

      session.parse(v3_response(session)).value.get_string.should eq("hostname")
    end
  end

  it "requires authentication for responses to an authenticated session" do
    manager = SNMP::V3::Session.new("user", "authkey1", engine_id: engine_id)
    responder = SNMP::V3::Session.new("user", engine_id: engine_id)

    expect_raises(SNMP::V3::Security::AuthenticationError, /security level/) do
      manager.parse(v3_response(responder))
    end
  end

  it "requires privacy for responses to an authPriv session" do
    manager = SNMP::V3::Session.new("user", "authkey1", "privkey1", engine_id,
      priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES)
    responder = SNMP::V3::Session.new("user", "authkey1", engine_id: engine_id)

    expect_raises(SNMP::V3::Security::AuthenticationError, /security level/) do
      manager.parse(v3_response(responder))
    end
  end

  it "requires the expected USM username and authoritative engine" do
    manager = SNMP::V3::Session.new("user", "authkey1", engine_id: engine_id)
    {
      SNMP::V3::Session.new("other", "authkey1", engine_id: engine_id),
      SNMP::V3::Session.new("user", "authkey1", engine_id: "8000000005060708"),
    }.each do |responder|
      expect_raises(SNMP::V3::Security::AuthenticationError, /security identity/) do
        manager.parse(v3_response(responder))
      end
    end
  end

  it "requires the session's security model for a response" do
    session = SNMP::V3::Session.new("user", "authkey1", engine_id: engine_id)

    expect_raises(SNMP::V3::Security::AuthenticationError, /security identity/) do
      session.parse(v3_response(session, security_model: SNMP::V3::SecurityModel::TSM))
    end
  end

  it "verifies the signature when the response security settings match" do
    manager = SNMP::V3::Session.new("user", "authkey1", engine_id: engine_id)
    responder = SNMP::V3::Session.new("user", "authkey2", engine_id: engine_id)

    expect_raises(SNMP::V3::Security::AuthenticationError, /message authentication failed/) do
      manager.parse(v3_response(responder))
    end
  end
end
