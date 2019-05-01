class SNMP::V3::Session
  def initialize(@username = "", @engine_id = "", @auth_protocol = Security::AuthProtocol::MD5, @priv_protocol = Security::PrivacyProtocol::DES, @auth_password = "", @priv_password = "")
  end

  property username : String
  property engine_id : String
  property auth_protocol : Security::AuthProtocol
  property priv_protocol : Security::PrivacyProtocol
  property auth_password : String
  property priv_password : String

  def engine_id_probe
    security_params = SecurityParams.new
    scoped_pdu = ScopedPDU.new(SNMP::Request::Get, SNMP::PDU.new)
    V3::Message.new(scoped_pdu, security_params, security_model: SecurityModel::Transport)
  end
end
