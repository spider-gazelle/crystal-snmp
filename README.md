# SNMP Support for Crystal Lang

[![CI](https://github.com/spider-gazelle/crystal-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/crystal-snmp/actions/workflows/ci.yml)

NOTE:: I consider the project ready to use. Usage won't change significantly between now and v1.0.0

## Usage

This library can be used to build either an SNMP Agent or Client application.
The examples below indicate how to use it as a client.

### SNMP v2c

```crystal
# Connect to server
socket = UDPSocket.new
socket.connect("demo.snmplabs.com", 161)
socket.sync = false

# Make request
session = SNMP::Session.new
socket.write_bytes session.get("1.3.6.1.2.1.1.4.0")
socket.flush

# Process response
response = session.parse(socket.read_bytes(ASN1::BER))
response.value.get_string # "SNMP Laboratories, info@snmplabs.com"
```

### SNMP v3

```crystal
# Connect to server
socket = UDPSocket.new
socket.connect("demo.snmplabs.com", 161)
socket.sync = false

# Setup session
session = SNMP::V3::Session.new("usr-md5-aes", "authkey1", "privkey1", priv_protocol: SNMP::V3::Security::PrivacyProtocol::AES)

# This is required to get the engine ID, boot and tick times
# You can read about it here: https://www.snmpsharpnet.com/?page_id=28
if session.must_revalidate?
  socket.write_bytes session.engine_validation_probe
  socket.flush
  session.validate socket.read_bytes(ASN1::BER)
end

# Make the request
# NOTE:: with SNMPv3 you need to prepare the message for transmission
unencrypted_message = session.get("1.3.6.1.2.1.1.4.0")
socket.write_bytes session.prepare(unencrypted_message)
socket.flush

# Process response
response = session.parse(socket.read_bytes(ASN1::BER))
response.value.get_string # "SNMP Laboratories, info@snmplabs.com"
```

### Setting values

NOTE:: `set` currently supports:

* Strings
* Integers
* Boolean
* Nil

More crystal classes will be added over time (such as `Float` and `Socket::IPAddress` etc)

```crystal
# Setting a string
session.set("1.3.6.1.2.1.1.3.0", "some string value")

# Setting an integer
session.set("1.3.6.1.2.1.1.3.0", 34)
```

For more complex or currently unsupported types you can build a custom ASN1.BER.

```crystal
ber = ASN1::BER.new
ber.tag_class = ASN1::BER::TagClass::Application
ber.tag_number = 12
ber.payload = Bytes[1,2,3,4,5]

session.set("1.3.6.1.2.1.1.3.0", ber)
```

### Extracting response values

The response value is always an `ASN1::BER`

```crystal
response = session.parse(socket.read_bytes(ASN1::BER))
response.value
```

You can extract common data types using helper methods:

* `.get_string`
* `.get_object_id` for SNMP OIDs such as 1.3.6.1.2.1
* `.get_hexstring` for a hex representation of the payload bytes
* `.get_bytes` for the raw byte data
* `.get_boolean`
* `.get_integer` returning an `Int64`


## Notes on IO

### Writing to Sockets

When writing SNMP messages to the socket, be aware that you should be buffering the write.

```crystal

session = SNMP::V3::Session.new
message = session.engine_validation_probe

# Ensure sync is false so the message is buffered
socket.sync = false
socket.write_bytes message

# This requires you to call `flush`
socket.flush

```

This is because the call to `to_io` on message involves multiple writes to the IO
as the message is progressively constructed. However you don't want each write to
be sending packets as this will result in a lot of overhead and most SNMP servers
will not accept fragmented messages.


### Reading from sockets

Whilst you'll probably be OK reading data like `socket.read_bytes(ASN1::BER)`
you should probably be buffering requests based on SNMP PDU Max Size (defaulting to 65507 bytes) and throwing away any buffered data that can't be read after buffering or a short timeout.
