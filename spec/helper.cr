require "spec"

TEST_SNMP_SERVER = ENV["TEST_SNMP_SERVER"]? || "localhost"
# Port of the live test agent — the CI starts an unprivileged snmpd on a high port.
TEST_SNMP_PORT = (ENV["TEST_SNMP_PORT"]? || "161").to_i

require "../src/snmp"
