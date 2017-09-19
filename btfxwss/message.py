import logging
import json

class Message:
    __slots__ = ['fields', 'key', 'secret', 'auth']

    def __init__(**fields, event=None, key=None, secret=None):
        self.fields = fields
        self.key = key
        self.secret = secret
        self.event = event

    def pack():
        if self.event == 'auth':
            nonce = str(int(time.time() * 10000000))
            auth_string = 'AUTH' + nonce
            auth_sig = hmac.new(self.secret.encode(), auth_string.encode(),
                                hashlib.sha384).hexdigest()

            payload = {'event': self.event, 'apiKey': self.key, 'authSig': auth_sig,
                       'authPayload': auth_string, 'authNonce': nonce}
            return json.dumps(payload)
        else:
            return json.dumps(self.fields)
