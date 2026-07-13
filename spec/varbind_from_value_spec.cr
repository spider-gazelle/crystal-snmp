require "./helper"

describe SNMP::VarBind do
  describe ".from_value" do
    oid = "1.3.6.1.2.1.1.5.0"

    it "encodes a String as an OctetString" do
      vb = SNMP::VarBind.from_value(oid, "sysname")
      vb.oid.should eq(oid)
      vb.value.get_string.should eq("sysname")
    end

    it "encodes an Int as an Integer" do
      vb = SNMP::VarBind.from_value(oid, 42)
      vb.value.get_integer.should eq(42)
    end

    it "encodes a Bool as a Boolean" do
      vb = SNMP::VarBind.from_value(oid, true)
      vb.value.get_boolean.should be_true
    end

    it "encodes Nil as a Null value" do
      vb = SNMP::VarBind.from_value(oid, nil)
      vb.value.tag.should eq(SNMP::UniversalTags::Null)
    end

    it "takes a pre-built ASN1::BER verbatim" do
      ber = ASN1::BER.new.set_integer(7)
      vb = SNMP::VarBind.from_value(oid, ber)
      vb.value.should be(ber)
    end

    it "re-oids a pre-built VarBind" do
      other = SNMP::VarBind.new("1.3.6.1.9.9.9.0")
      other.value.set_string("kept")
      vb = SNMP::VarBind.from_value(oid, other)
      vb.should be(other)
      vb.oid.should eq(oid)
      vb.value.get_string.should eq("kept")
    end

    it "rejects an unsupported value type" do
      expect_raises(ArgumentError, /unsupported varbind value/) do
        SNMP::VarBind.from_value(oid, 1.5)
      end
    end
  end
end
