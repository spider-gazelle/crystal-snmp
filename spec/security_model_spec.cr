require "./helper"

describe SNMP::V3::SecurityModel do
  it "uses the IANA SnmpSecurityModel numbers" do
    SNMP::V3::SecurityModel::SNMPv1.value.should eq(1)
    SNMP::V3::SecurityModel::SNMPv2c.value.should eq(2)
    SNMP::V3::SecurityModel::USM.value.should eq(3)
  end
end

describe SNMP::V3::Security do
  it "reports USM as its security model" do
    SNMP::V3::Security.new("user", auth_password: "password").security_model.should eq(SNMP::V3::SecurityModel::USM)
  end
end
