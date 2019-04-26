# This is not really a PDU, but a container for a PDU
class SNMP::V3::Session
  def initialize(@username, @auth_protocol = Security::AuthProtocol::MD5, @priv_protocol = Security::PrivacyProtocol::DES, @auth_password = "", @priv_password = "")
  end

  property username : String
  property engine_id : String?
  property auth_protocol : Security::AuthProtocol
  property priv_protocol : Security::PrivacyProtocol
  property auth_password : String
  property priv_password : String

  def probe_for_engine
    security_params = Security.new(@username)
    pdu = ScopedPDU.new(Request::Get)
    encoded_report_pdu = Message.encode(pdu, security_params)

    # TODO:: needs a client to send the message
    # response = client.send encoded_report_pdu

    #_, engine_id, @engine_boots, @engine_time = decode(encoded_response_pdu, security_parameters: report_sec_params)
    #engine_id
  end
end
