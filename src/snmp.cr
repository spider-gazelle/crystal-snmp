require "bindata/asn1"

class SNMP
  module V3
  end

  # SNMP version codes
  enum Version
    V1
    V2C
    V3  = 3
  end

  enum Request
    Get
    GetNext
    Response
    Set
    V1_Trap
    GetBulk
    Inform
    V2_Trap
    Report
  end

  enum GenericTrap
    ColdStart
    WarmStart
    LinkDown
    LinkUp
    AuthenticationFailure
    EGPNeighborLoss
    EnterpriseSpecific
  end

  enum ErrorStatus
    NoError
    TooBig
    NoSuchName
    BadValue
    ReadOnly
    GeneralError
    AccessDenied
    WrongType
    WrongLength
    WrongEncoding
    WrongValue
    NoCreation
    InconsistentValue
    ResourceUnavailable
    CommitFailed
    UndoFailed
    AuthorizationError
    NotWritable
    InconsistentName
  end

  # Custom SNMP tags on varbinds
  enum AppTags
    IPAddress
    Counter32
    Gauge32 # unsigned integer
    TimeTicks
    Opaque
    # missing 5
    Counter64 = 6
  end

  def self.parse(message : ASN1::BER, session = nil) : Message | V3::Message
    snmp = message.children
    version = Version.from_value(snmp[0].get_integer)

    case version
    when Version::V3
      V3::Message.new(snmp, session)
    else
      Message.new(snmp)
    end
  end
end

require "./snmp/message"
require "./snmp/v3/message"
require "./snmp/v3/session"
