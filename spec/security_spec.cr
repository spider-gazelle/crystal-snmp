require "./helper"

describe SNMP::Security do
  it "should init a security helper" do
    engine_id = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    sec = SNMP::Security.new("steve", engine_id)

    # password too short
    expect_raises(Exception) do
      sec = SNMP::Security.new("steve", engine_id, auth_password: "123")
    end
  end

  # FROM https://tools.ietf.org/html/rfc3414#appendix-A.2.1
  it "should generate correct passkeys" do
    engine_id = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    password = "maplesyrup"

    sec = SNMP::Security.new("username", engine_id, auth_password: password)
    sec.passkey(password).should eq(Bytes[0x9f, 0xaf, 0x32, 0x83, 0x88, 0x4e, 0x92, 0x83, 0x4e, 0xbc, 0x98, 0x47, 0xd8, 0xed, 0xd9, 0x63])

    sec = SNMP::Security.new("username", engine_id, SNMP::Security::AuthProtocol::SHA, password, priv_password: "maplesyrup")
    sec.passkey(password).should eq(Bytes[0x9f, 0xb5, 0xcc, 0x03, 0x81, 0x49, 0x7b, 0x37, 0x93, 0x52, 0x89, 0x39, 0xff, 0x78, 0x8d, 0x5d, 0x79, 0x14, 0x52, 0x11])
  end

  it "should generate correct keys" do
    engine_id = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    password = "maplesyrup"

    sec = SNMP::Security.new("username", engine_id, SNMP::Security::AuthProtocol::MD5, password, priv_password: "maplesyrup")
    sec.auth_key.should eq(Bytes[0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b])
    sec.priv_key.should eq(Bytes[0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b])

    sec = SNMP::Security.new("username", engine_id, SNMP::Security::AuthProtocol::SHA, password, priv_password: "maplesyrup")
    sec.auth_key.should eq(Bytes[0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f])
    sec.priv_key.should eq(Bytes[0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f])
  end

  it "should know when to revalidate" do
    engine_id = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    password = "maplesyrup"
    sec = SNMP::Security.new("username", engine_id, SNMP::Security::AuthProtocol::MD5, password, priv_password: "maplesyrup")

    sec.must_revalidate?.should eq(true)

    sec.engine_id = "NEWENGINE".to_slice
    sec.must_revalidate?.should eq(false)

    sec.timeliness = Time.monotonic.to_i - 150
    sec.must_revalidate?.should eq(true)

    sec.engine_id = "UPDATEDENGINE".to_slice
    sec.must_revalidate?.should eq(false)
  end
end
