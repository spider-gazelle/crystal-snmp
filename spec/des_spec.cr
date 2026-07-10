require "./helper"

describe SNMP::V3::Security::DES do
  # RFC 3414 8.1.1.2: the ciphertext is the zero-padded plaintext, same length —
  # no PKCS block-cipher padding is added.
  it "zero-pads to the block size without an extra PKCS block", tags: "legacy" do
    des = SNMP::V3::Security::DES.new(Bytes.new(16) { |i| (i + 1).to_u8 })
    data = "hello world!".to_slice # 12 bytes → padded to 16

    encrypted, salt = des.encrypt(data, 1_u32)
    encrypted.size.should eq(16)

    decrypted = des.decrypt(encrypted, salt, 1_u32).to_slice
    decrypted[0, data.size].should eq(data)
  end
end
