# this is the server, s4p32a.py is the attack

import secrets
import time
import sha1old as sha1

from flask import Flask, request

SECURE_KEY = secrets.token_bytes(16)

def gen_hmac(msg):
    return sha1.sha1(SECURE_KEY + msg).hexdigest()

app = Flask(__name__)

@app.route("/", methods = ["GET"])
def insecure_compare():
    real_hmac, test_hmac = gen_hmac(request.args.get("file").encode()), request.args.get("hmac")
    print(real_hmac, test_hmac)

    for i in range(len(real_hmac)):
        if real_hmac[i] != test_hmac[i]:
            return "False", 500
        time.sleep(1 / 1000) # 1 is in ms
    return "True", 200