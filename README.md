# SNMP Support for Crystal Lang

[![Build Status](https://travis-ci.org/spider-gazelle/crystal-snmp.svg?branch=master)](https://travis-ci.org/spider-gazelle/crystal-snmp)


## Writing to Sockets

When writing SNMP messages to the socket, be aware that you should be buffering the write.

```crystal

session = SNMP::V3::Session.new
message = session.engine_id_probe

# buffer the message
socket.sync = false
socket.write_bytes message
socket.flush

```

This is because the call to `to_io` on message involves multiple writes to the IO
as the message is progressively constructed. However you don't want each write to
be sending packets as this will result in a lot of overhead and most SNMP servers
will not accept fragmented messages.
