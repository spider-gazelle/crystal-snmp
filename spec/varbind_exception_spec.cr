require "./helper"

# Build a varbind whose value is an SNMPv2 exception (context-specific primitive).
private def exception_varbind(tag_number)
  vb = SNMP::VarBind.new("1.3.6.1.2.1.1.1.0")
  vb.value.tag_class = ASN1::BER::TagClass::ContextSpecific
  vb.value.tag_number = tag_number
  vb
end

describe SNMP::VarBind do
  it "recognises endOfMibView (context 2)" do
    vb = exception_varbind(2)
    vb.end_of_mib_view?.should be_true
    vb.exception?.should be_true
    vb.no_such_object?.should be_false
  end

  it "recognises noSuchObject (context 0) and noSuchInstance (context 1)" do
    exception_varbind(0).no_such_object?.should be_true
    exception_varbind(1).no_such_instance?.should be_true
    exception_varbind(0).end_of_mib_view?.should be_false
  end

  it "does not flag an ordinary value as an exception" do
    vb = SNMP::VarBind.new("1.3.6.1.2.1.1.1.0")
    vb.value.set_string("a regular value")
    vb.exception?.should be_false
    vb.end_of_mib_view?.should be_false
  end
end
