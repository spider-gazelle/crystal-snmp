require "bindata/asn1"

class SNMP
  alias UniversalTags = ASN1::BER::UniversalTags

  module V3
    # SNMPv3 message flags describing the features used
    @[Flags]
    enum MessageFlags
      # privacy without authentication is not allowed
      Authentication

      # encryption applied?
      Privacy

      # Report PDU must be returned to the sender under those conditions that can cause the generation of a Report PDU
      # when the flag is zero, a Report PDU may not be sent.
      # The reportableFlag is set to 1 by the sender in all messages containing a request (Get, Set) or an Inform, and set to 0 for messages containing a Response, a Trap, or a Report PDU
      # It is used only in cases in which the PDU portion of the message cannot be decoded (for example, when decryption fails because of incorrect key)
      Reportable
    end

    # IANA SnmpSecurityModel numbers (RFC 3411).
    #
    # For USM, the "authoritative" engine rules apply: when a message expects a
    # response (Get, GetNext, GetBulk, Set, or Inform) the receiver is authoritative;
    # when it does not (SNMPv2-Trap, Response, or Report) the sender is authoritative.
    enum SecurityModel
      Any     = 0
      SNMPv1  = 1
      SNMPv2c = 2
      USM     = 3
      TSM     = 4 # Transport Security Model (DTLS)
    end
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

  # PDU error-status codes (RFC 3416). error-index is a plain 1-based varbind
  # position, not an enum — see `PDU#error_index`.
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

  def self.parse(message : ASN1::BER, security = nil) : Message | V3::Message
    snmp = ber_fields(message, 1, "SNMP message")
    version = decode_enum(Version, snmp[0].get_integer, "SNMP version")

    case version
    when Version::V3
      V3::Message.new(snmp, security)
    else
      Message.new(snmp)
    end
  end
end

require "./snmp/error"
require "./snmp/values"
require "./snmp/message"
require "./snmp/session"
require "./snmp/v3/message"
require "./snmp/v3/session"
require "./snmp/client"
require "./snmp/helpers/*"
