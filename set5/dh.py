import secrets 

class DiffieHellman():
    def __init__(self, p, g):
        self.p = p 
        self.g = g 
        self.private_key = secrets.randbelow(p)
        self.shared_key = -1

    def get_private_key(self):
        return self.private_key 

    def get_public_key(self):
        return pow(self.g, self.private_key, self.p)

    def get_shared_key(self, other_key = -1):
        if self.shared_key == -1:
            self.shared_key = pow(other_key, self.private_key, self.p)
        return self.shared_key