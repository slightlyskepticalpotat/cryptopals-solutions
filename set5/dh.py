import secrets 

class DiffieHellman():
    def __init__(self, p, g):
        self.p = p 
        self.g = g 
        self.private_key = secrets.randbelow(p)

    def get_private_key(self):
        return self.private_key 

    def get_public_key(self):
        self.public_key = pow(self.g, self.get_private_key(), self.p)
        return self.public_key 

    def get_shared_key(self, other_key = -1):
        self.shared_key = pow(other_key, self.get_private_key(), self.p)
        return self.shared_key