import json
import uuid
import base64
from security_manager import SecurityManager
from rsa_message_crypto import RSAMessageCrypto
from pub_sub import Publisher
from datetime import datetime, UTC


class SecureSender:
    def __init__(self, sender: Publisher):
        self.security = SecurityManager()
        self.crypto = RSAMessageCrypto()
        self.sender = sender

    def encrypt_message(self, command, main_name):
        """Verschlüsselt eine Nachricht mit verbessertem Padding"""
        try:
            public_key = self.crypto.get_public_key()
            session_key = self.security.generate_session_key()
            salt = self.security.generate_salt()
            iv = self.security.generate_iv()
            
            derived_key = self.security.derive_key(session_key, salt)
            
            if isinstance(command, str):
                command = command.encode()
            
            # Bereite Daten vor und führe Padding durch
            padded_data = self.security.pad_data(command)
            
            # Encrypt symetric the command data
            encrypted_command = self.security.encrypt_symmetric(padded_data, derived_key, iv)
            # Encrypt assymmetric the session key
            encrypted_session_key = self.security.encrypt_asymmetric(session_key, public_key)

            return {
                 main_name : base64.b64encode(encrypted_command).decode(),
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode()
            }

        except Exception as e:
            print(f"Verschlüsselungsfehler: {str(e)}")
            raise
    
    def send_command(self, command):
        try:
            message_id = str(uuid.uuid4())
            current_time = datetime.now(UTC)
            
            encrypted_info = self.encrypt_message(command, 'command')
            original_hash = self.security.hash_with_salt(command)
            
            # Innere Datenstruktur
            data = {
                "message_id": message_id,
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "sender_id": "betzhbaur",
                "key_id": "uniqe_key-id",
                "message_version": "1.0",
                **encrypted_info,
                "original_hash": original_hash['hash'],
                "original_salt": original_hash['salt']
            }
            
            # Verschlüssele die gesamten Daten nochmals
            hash_payload = self.security.hash(json.dumps(data), salt='')
            outer_encryption = self.encrypt_message(hash_payload['hash'], 'security_hash')
            
            # Äußere Datenstruktur
            message = {
                "data": data,
                **outer_encryption
            }
            self.sender.write(json.dumps(message))


            print(f"\nNachricht gesendet:")
            print(f"Message ID: {message_id}")
            print(f"Zeitstempel: {current_time}")
        except Exception as e:
            print(f"Sendefehler: {str(e)}")
            raise