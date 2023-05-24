import binascii
import random
import re
import gmpy2

from rsa import RSA
from sha1old import sha1

ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
KEY_LENGTH = 1024

class Signatures(RSA):
    def sign(self, msg):
        return self.decrypt(int.from_bytes(msg, "big"))
    
    def verify(self, msg, sig):
        loc = self.encrypt(int(binascii.hexlify(sig), 16))
        sig = b"\x00" + loc.to_bytes((loc.bit_length()+7)//8, "big")
        # verify sig has block in pkcs 1.5 (vuln)
        check = re.compile(b"\x00\x01\xff+?\x00.{15}(.{20})", re.DOTALL).match(sig)
        if not check:
            return False
        hash = check.group(1)
        return hash == binascii.unhexlify(sha1(msg).hexdigest())

msg = b"hi mom"
block = b"\x00\x01\xff\x00" + ASN1_SHA1 + binascii.unhexlify(sha1(msg).hexdigest())
garbage = (((KEY_LENGTH + 7) // 8) - len(block)) * b"\x00"
block += garbage
pre_enc = int.from_bytes(block, "big")
fake_sig = int(gmpy2.iroot(pre_enc, 3)[0] + 1)
ree = Signatures(KEY_LENGTH, 3)
fake_sig = fake_sig.to_bytes((fake_sig.bit_length()+7)//8, "big")
print(ree.verify(msg, fake_sig))
