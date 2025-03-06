from datetime import datetime, UTC, timedelta
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP, AES
import hashlib
import base64

class SecurityManager:
    def __init__(self):
        self.salt_length = 16
        self.iv_length = 16
        self.key_length = 32
        self.pbkdf2_iterations = 100000
        self.processed_messages = set()
        self.max_message_age = timedelta(minutes=5)
        self.cleanup_threshold = 1000

    def generate_salt(self):
        return get_random_bytes(self.salt_length)

    def generate_iv(self):
        return get_random_bytes(self.iv_length)

    def generate_session_key(self):
        return get_random_bytes(self.key_length)

    def derive_key(self, base_key, salt):
        return PBKDF2(base_key, salt, dkLen=self.key_length, 
                     count=self.pbkdf2_iterations)

    def hash_with_salt(self, data):
        return self.hash(data, None)

    def hash(self, data, salt=''):
        if isinstance(data, str):
            data = data.encode()
        if isinstance(salt, str):
            salt = salt.encode()
        elif not salt:
            salt = self.generate_salt()
        
        salted_data = salt + data
        hash_value = hashlib.sha384(salted_data).hexdigest()
        
        return {
            'hash': hash_value,
            'salt': base64.b64encode(salt).decode()
        }

    def validate_message(self, message_dict, current_time=None):
        if current_time is None:
            current_time = datetime.now(UTC)

        try:
            # Parse message timestamp
            message_time = datetime.strptime(
                message_dict['timestamp'], 
                '%Y-%m-%d %H:%M:%S'
            ).replace(tzinfo=UTC)
        except (ValueError, KeyError):
            return False, "Ungültiger Zeitstempel"

        # Überprüfe Message-ID
        message_id = message_dict.get('message_id')
        if not message_id:
            return False, "Keine Message-ID"
        
        if message_id in self.processed_messages:
            return False, "Message-ID bereits verwendet"

        # Überprüfe Zeitstempel
        time_diff = current_time - message_time
        if time_diff > self.max_message_age:
            return False, "Nachricht zu alt"
        if time_diff < timedelta(seconds=-30):
            return False, "Nachricht aus der Zukunft"

        # Speichere Message-ID
        self.processed_messages.add(message_id)
        
        # Cleanup wenn nötig
        if len(self.processed_messages) > self.cleanup_threshold:
            self._cleanup_old_messages(current_time)
        
        return True, "OK"

    def _cleanup_old_messages(self, current_time):
        cutoff_time = current_time - self.max_message_age
        self.processed_messages = {
            msg_id for msg_id in self.processed_messages
            if msg_id > cutoff_time.strftime('%Y%m%d%H%M%S')
        }
    
    def pad_data(self, data):
        """Führt ein konsistentes Padding der Daten durch"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        block_size = AES.block_size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, padded_data):
        """Entfernt das Padding sicher"""
        if not padded_data:
            raise ValueError("Keine Daten zum Entpadden")
        
        padding_length = padded_data[-1]
        if padding_length > AES.block_size:
            raise ValueError("Ungültiges Padding")
            
        if padding_length > len(padded_data):
            raise ValueError("Padding länger als Daten")
            
        for i in range(padding_length):
            if padded_data[-(i+1)] != padding_length:
                raise ValueError("Inkonsistentes Padding")
                
        return padded_data[:-padding_length]

    def encrypt_symmetric(self, data, key, iv):
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        return cipher_aes.encrypt(data)
    
    def decrypt_symmetric(self, data, key, iv):
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        return cipher_aes.decrypt(data)

    def encrypt_asymmetric(self, data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(data)
    
    def decrypt_asymmetric(self, data, private_key):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(data)