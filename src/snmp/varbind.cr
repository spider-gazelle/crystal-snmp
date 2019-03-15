class SNMP
  class VarBind
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
  end
end
