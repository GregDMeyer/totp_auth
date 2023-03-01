import time,base64,hashlib,hmac
mac=hmac.new(
    base64.b32decode('DUMMYKEY'),
    (int(time.time())//30).to_bytes(byteorder='big',length=8),
    hashlib.sha1
).digest()
print(str(int.from_bytes(mac[int(mac[-1])&0xF:][:4],byteorder='big')&0x7FFFFFFF)[-6:])
