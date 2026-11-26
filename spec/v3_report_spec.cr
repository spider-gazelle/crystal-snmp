require "./helper"

# Build a Report V3::Message carrying a usmStats varbind + engine params.
private def report_message(stat_oid, engine_id = "8000000001020304", boots = 7, time = 42_000)
  pdu = SNMP::PDU.new(request_id: 1, varbinds: [SNMP::VarBind.new(stat_oid)])
  scoped = SNMP::V3::ScopedPDU.new(SNMP::Request::Report, pdu, engine_id)
  params = SNMP::V3::SecurityParams.new("user", engine_id, boots, time)
  SNMP::V3::Message.new(scoped, params, security_model: SNMP::V3::SecurityModel::USM)
end

private def report_reply(request : SNMP::V3::Message, stat : SNMP::V3::UsmStat, engine_id, boots, time, security = nil)
  report = report_message("#{SNMP::V3::USM_STATS_BASE}.#{stat.value}.0", engine_id, boots, time)
  report.id = request.id
  if security
    report.request_id = request.request_id
    report.flags = SNMP::V3::MessageFlags::Authentication
    report.sign(security)
  else
    report.request_id = 0
    report.flags = SNMP::V3::MessageFlags::None
  end
  report
end

private class ReportTestSession < SNMP::V3::Session
  @last_message_id = 0

  def get(oid : String)
    @last_message_id += 1
    super(oid, request_id: 42, message_id: @last_message_id)
  end
end

private def aes_report_test_security(engine_id)
  SNMP::V3::Security.new("user", engine_id, auth_password: "authkey1",
    priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES, priv_password: "privkey1")
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

describe SNMP::Client do
  describe "SNMPv3 Report recovery" do
    engine_id = "8000000001020304"
    oid = "1.3.6.1.2.1.1.5.0"

    it "rebuilds and authenticates the retry for the newly discovered engine" do
      next_engine_id = "8000000005060708"
      session = ReportTestSession.new(aes_report_test_security(engine_id))
      session.validate(report_message("#{SNMP::V3::USM_STATS_BASE}.4.0", engine_id, 1, 10))

      previous_security = aes_report_test_security(engine_id)
      next_security = aes_report_test_security(next_engine_id)
      script = ->(agent : LoopbackAgent) do
        message, peer = agent.receive(previous_security)
        initial = message.as(SNMP::V3::Message)
        initial.engine_id.should eq(engine_id)
        initial.security_params.engine_boots.should eq(1)
        initial.security_params.engine_time.should eq(10)
        recovery = report_reply(initial, SNMP::V3::UsmStat::UnknownEngineID, next_engine_id, 2, 20)
        agent.send(recovery, peer)

        message, peer = agent.receive(next_security)
        retry_request = message.as(SNMP::V3::Message)
        retry_request.request.should eq(SNMP::Request::Get)
        retry_request.oid.should eq(oid)
        retry_request.engine_id.should eq(next_engine_id)
        retry_request.scoped_pdu.context_engine_id.should eq(next_engine_id)
        retry_request.security_params.engine_boots.should eq(2)
        retry_request.security_params.engine_time.should eq(20)

        # A delayed copy of the first request's Report arrives before the reply.
        agent.send(recovery, peer)

        responder = SNMP::V3::Session.new(next_security)
        responder.validate(recovery)
        response = responder.set(oid, "hostname", retry_request.request_id, retry_request.id)
        response.request = SNMP::Request::Response
        response.flags = next_security.security_level
        agent.send(responder.prepare(response), peer)
      end

      with_loopback_client(script, session: session) do |client|
        client.get(oid).value.get_string.should eq("hostname")
        session.engine_id.should eq(next_engine_id)
      end
    end

    it "raises ReportError if the time-window Report persists after one retry" do
      stat = SNMP::V3::UsmStat::NotInTimeWindow
      session = ReportTestSession.new("user", "authkey1", engine_id: engine_id)
      session.validate(report_message("#{SNMP::V3::USM_STATS_BASE}.4.0", engine_id, 1, 10))
      security = SNMP::V3::Security.new("user", engine_id, auth_password: "authkey1")
      script = ->(agent : LoopbackAgent) do
        message, peer = agent.receive(security)
        initial = message.as(SNMP::V3::Message)
        agent.send(report_reply(initial, stat, engine_id, 2, 20, security), peer)

        message, peer = agent.receive(security)
        retry_request = message.as(SNMP::V3::Message)
        retry_request.oid.should eq(oid)
        retry_request.security_params.engine_boots.should eq(2)
        retry_request.security_params.engine_time.should eq(20)
        agent.send(report_reply(retry_request, stat, engine_id, 2, 20, security), peer)
      end

      with_loopback_client(script, session: session) do |client|
        error = expect_raises(SNMP::V3::Security::ReportError) { client.get(oid) }
        error.usm_stat.should eq(stat)
      end
    end

    it "raises ReportError immediately for a non-recoverable Report" do
      stat = SNMP::V3::UsmStat::UnknownUserName
      script = ->(agent : LoopbackAgent) do
        message, peer = agent.receive
        agent.send(report_reply(message.as(SNMP::V3::Message), stat, engine_id, 2, 20), peer)
      end

      with_loopback_client(script, session: ReportTestSession.new("user", engine_id: engine_id)) do |client|
        error = expect_raises(SNMP::V3::Security::ReportError) { client.get(oid) }
        error.usm_stat.should eq(stat)
      end
    end
  end
end
