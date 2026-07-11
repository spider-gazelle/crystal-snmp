require "./helper"

# Build a Report V3::Message carrying a usmStats varbind + engine params.
private def report_message(stat_oid, engine_id = "8000000001020304", boots = 7, time = 42_000)
  pdu = SNMP::PDU.new(request_id: 1, varbinds: [SNMP::VarBind.new(stat_oid)])
  scoped = SNMP::V3::ScopedPDU.new(SNMP::Request::Report, pdu, engine_id)
  params = SNMP::V3::SecurityParams.new("user", engine_id, boots, time)
  SNMP::V3::Message.new(scoped, params, security_model: SNMP::V3::SecurityModel::USM)
end

describe SNMP::V3::UsmStat do
  it "maps a usmStats OID (with instance suffix) to its counter" do
    SNMP::V3::UsmStat.from_oid?("1.3.6.1.6.3.15.1.1.2.0").should eq(SNMP::V3::UsmStat::NotInTimeWindow)
    SNMP::V3::UsmStat.from_oid?("1.3.6.1.6.3.15.1.1.4.0").should eq(SNMP::V3::UsmStat::UnknownEngineID)
    SNMP::V3::UsmStat.from_oid?("1.3.6.1.2.1.1.1.0").should be_nil
  end

  it "marks only notInTimeWindow / unknownEngineID as resyncable" do
    SNMP::V3::UsmStat::NotInTimeWindow.resyncable?.should be_true
    SNMP::V3::UsmStat::UnknownEngineID.resyncable?.should be_true
    SNMP::V3::UsmStat::WrongDigest.resyncable?.should be_false
  end
end

describe SNMP::V3::Message do
  it "recognises a Report PDU and its usmStats counter" do
    msg = report_message("1.3.6.1.6.3.15.1.1.2.0")
    msg.report?.should be_true
    msg.usm_stat.should eq(SNMP::V3::UsmStat::NotInTimeWindow)
  end

  it "is not a report for an ordinary response" do
    session = SNMP::V3::Session.new("user")
    session.get("1.3.6.1.2.1.1.1.0").report?.should be_false
  end
end

describe SNMP::V3::Session do
  it "resyncs engine id / boots / time from a Report" do
    session = SNMP::V3::Session.new("user")
    session.resync_from(report_message("1.3.6.1.6.3.15.1.1.4.0", engine_id: "800000abcd", boots: 9, time: 12_345))

    session.engine_id.should eq("800000abcd")
    session.engine_boots.should eq(9)
    session.engine_time.should eq(12_345)
  end
end
