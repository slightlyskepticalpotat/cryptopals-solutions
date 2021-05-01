import sha1
import secrets

SECURE_KEY = secrets.token_bytes(16)

def gen_hmac(msg):
    return sha1.sha1(SECURE_KEY + msg).hexdigest()

def test_hmac(msg, hmac):
    return sha1.sha1(SECURE_KEY + msg).hexdigest() == hmac

real_msg = b"now is the time for all good men to come to the aid of the party"
fake_msg = b"now is the time for all evil men to come to the aid of the party"
hmac = gen_hmac(real_msg)
print("real message:", test_hmac(real_msg, hmac))
print("fake message:", test_hmac(fake_msg, hmac))
