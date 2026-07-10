require "./helper"

# Build an authenticated inbound message carrying a given (boots, time).
private def auth_message(boots, time)
  params = SNMP::V3::SecurityParams.new("user", "000000000000000000000002", boots, time)
  scoped = SNMP::V3::ScopedPDU.new(SNMP::Request::Get, SNMP::PDU.new)
  msg = SNMP::V3::Message.new(scoped, params, security_model: SNMP::V3::SecurityModel::USM)
  msg.flags = SNMP::V3::MessageFlags::Authentication
  msg
end

# A session whose local notion of the remote engine is seeded via discovery.
private def seeded_session(boots, time)
  session = SNMP::V3::Session.new("user")
  probe = session.engine_validation_probe
  probe.engine_id = "000000000000000000000002"
  probe.security_params.engine_boots = boots
  probe.security_params.engine_time = time
  session.validate(probe)
  session
end

describe SNMP::V3::Session do
  describe "#check_timeliness" do
    it "accepts a message inside the window and advances the local notion of time" do
      session = seeded_session(5, 10_000)
      session.check_timeliness(auth_message(5, 10_050))
      session.engine_boots.should eq(5)
      session.engine_time.should eq(10_050)
    end

    it "rejects a replayed message with an older time under the same boots" do
      session = seeded_session(5, 10_000)
      expect_raises(SNMP::V3::Security::NotInTimeWindowError) do
        session.check_timeliness(auth_message(5, 9_000))
      end
    end

    it "rejects a message whose engine boots regressed" do
      session = seeded_session(5, 10_000)
      expect_raises(SNMP::V3::Security::NotInTimeWindowError) do
        session.check_timeliness(auth_message(4, 10_000))
      end
    end

    it "accepts a reboot (higher boots) and resets the time baseline" do
      session = seeded_session(5, 10_000)
      session.check_timeliness(auth_message(6, 3))
      session.engine_boots.should eq(6)
      session.engine_time.should eq(3)
    end

    it "does not enforce the window on unauthenticated messages" do
      session = seeded_session(5, 10_000)
      msg = auth_message(4, 9_000)
      msg.flags = SNMP::V3::MessageFlags::Reportable
      # boots regressed and time is stale, but with no auth there is nothing to replay
      session.check_timeliness(msg)
    end
  end
end
