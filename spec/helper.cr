require "spec"

{% if compare_versions(Crystal::VERSION, "1.21.0") >= 0 && !flag?(:without_mt) && !flag?(:preview_mt) %}
  if workers = ENV["SNMP_SPEC_WORKERS"]?
    Fiber::ExecutionContext.default.resize(workers.to_i)
  end
{% end %}

TEST_SNMP_SERVER = ENV["TEST_SNMP_SERVER"]? || "localhost"
# Port of the live test agent — the CI starts an unprivileged snmpd on a high port.
TEST_SNMP_PORT = (ENV["TEST_SNMP_PORT"]? || "161").to_i

require "../src/snmp"
