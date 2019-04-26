class SNMP::VarBind
  def initialize(ber : ASN1::BER)
    varbind = ber.children
    @oid = varbind[0].get_object_id
    @value = varbind[1]
  end

  def initialize(@oid)
    @value = ASN1::BER.new
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
      SNMP.set_{{helpers.id}}(self.value, data)
      self
    end
  {% end %}
end
