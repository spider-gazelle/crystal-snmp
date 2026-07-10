class SNMP::VarBind
  def initialize(ber : ASN1::BER)
    varbind = ber.children
    @oid = varbind[0].get_object_id
    @value = varbind[1]
  end

  def initialize(@oid, tag_number = UniversalTags::Null)
    @value = ASN1::BER.new
    @value.tag_number = tag_number
  end

  property oid : String
  property value : ASN1::BER

  def to_ber
    id = ASN1::BER.new
    id.set_object_id(@oid)

    varb = ASN1::BER.new
    varb.tag_number = ASN1::BER::UniversalTags::Sequence
    varb.children = {id, @value}
    varb
  end

  {% for helpers in [:unsigned64, :unsigned32] %}
    def get_{{helpers.id}}
      SNMP.get_{{helpers.id}}(self.value)
    end

    def set_{{helpers.id}}(data)
      SNMP.set_{{helpers.id}}(data, self.value)
      self
    end
  {% end %}

  # SNMPv2 (RFC 3416) exception values are context-specific primitives carried
  # in place of the varbind value. Detect them via the tag class + number
  # directly (the `#tag` shortcut only accepts universal tags).
  private def exception_tag?(number : Int) : Bool
    value.tag_class == ASN1::BER::TagClass::ContextSpecific && value.tag_number.to_i == number
  end

  # noSuchObject[0] — the requested object does not exist.
  def no_such_object?
    exception_tag?(0)
  end

  # noSuchInstance[1] — the object exists but this instance does not.
  def no_such_instance?
    exception_tag?(1)
  end

  # endOfMibView[2] — a GetNext/GetBulk walked past the end of the MIB view.
  def end_of_mib_view?
    exception_tag?(2)
  end

  # True for any of the three SNMPv2 exception values.
  def exception?
    no_such_object? || no_such_instance? || end_of_mib_view?
  end

  # Proxy missing methods to the BER value
  macro method_missing(call)
    self.value.{{call.name.id}}({{*call.args}})
  end
end
