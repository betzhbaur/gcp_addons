import os
from Crypto.PublicKey import RSA

class RSAMessageCrypto:
    def __init__(self):
        self.keys_directory = "secure_keys"
        self._ensure_keys_directory()

    def _ensure_keys_directory(self):
        if not os.path.exists(self.keys_directory):
            os.makedirs(self.keys_directory)
            self.generate_new_keypair()
        elif not os.path.exists(f"{self.keys_directory}/public_key.pem"):
            self.generate_new_keypair()


    def generate_new_keypair(self):
        key = RSA.generate(2048)
        with open(f"{self.keys_directory}/private_key.pem", 'wb') as f:
            f.write(key.export_key('PEM'))
        
        with open(f"{self.keys_directory}/public_key.pem", 'wb') as f:
            f.write(key.publickey().export_key('PEM'))
        
    def get_private_key(self):
        with open(f"{self.keys_directory}/private_key.pem", 'rb') as f:
            return RSA.import_key(f.read())

    def get_public_key(self):
        with open(f"{self.keys_directory}/public_key.pem", 'rb') as f:
            return RSA.import_key(f.read())
    
    