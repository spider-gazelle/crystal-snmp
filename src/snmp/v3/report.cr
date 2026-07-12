module SNMP::V3
  # Subtree of the RFC 3414 usmStats counters, reported to a manager via a
  # Report PDU (e.g. after a time-window or engine-id mismatch).
  USM_STATS_BASE = "1.3.6.1.6.3.15.1.1"

  # The usmStats counters (RFC 3414 5). A Report PDU names exactly one.
  enum UsmStat
    UnsupportedSecLevel = 1
    NotInTimeWindow     = 2
    UnknownUserName     = 3
    UnknownEngineID     = 4
    WrongDigest         = 5
    DecryptionError     = 6

    # Map a reported OID (with or without its trailing `.0` instance) to the
    # counter, or nil if it is not under the usmStats subtree.
    def self.from_oid?(oid : String) : UsmStat?
      return nil unless oid.starts_with?("#{USM_STATS_BASE}.")
      arc = oid[(USM_STATS_BASE.size + 1)..].split('.', 2).first
      num = arc.to_i?
      num ? from_value?(num) : nil
    end

    # Recoverable by re-syncing the engine params and retrying the request once.
    # The other counters signal a configuration error where a retry is futile.
    def resyncable? : Bool
      self == NotInTimeWindow || self == UnknownEngineID
    end
  end
end
