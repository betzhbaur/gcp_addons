from security_manager import SecurityManager
from rsa_message_crypto import RSAMessageCrypto
import json
import base64
from pub_sub import Subscriber

class SecureReceiver:
    def __init__(self, receiver: Subscriber):
        self.receiver = receiver
        self.security = SecurityManager()
        self.crypto = RSAMessageCrypto()

    def verify_outer_hash(self, data, encrypted_hash_info):
        """Verifiziert den äußeren Hash der Nachricht"""
        try:
            # Entschlüssele den Hash
            decrypted_hash = self.decrypt_message(encrypted_hash_info, 'security_hash')
            
            # Berechne Hash der Daten
            calculated_hash = self.security.hash(json.dumps(data), salt='')['hash']
            
            return decrypted_hash == calculated_hash
        except Exception as e:
            print(f"Hash-Verifizierungsfehler: {str(e)}")
            return False

    def verify_command_hash(self, command, original_hash, original_salt):
        """Verifiziert den Hash des entschlüsselten Befehls"""
        calculated_hash = self.security.hash(command, 
                                          base64.b64decode(original_salt))['hash']
        return calculated_hash == original_hash
    
    def decrypt_message(self, encrypted_info, command_name='command'):
        """Entschlüsselt eine Nachricht mit verbesserter Fehlerbehandlung"""
        try:
            # Lade Private Key
            private_key = self.crypto.get_private_key()

            # Decodiere alle base64-codierten Werte
            try:
                encrypted_session_key = base64.b64decode(encrypted_info['encrypted_session_key'])
                encrypted_data = base64.b64decode(encrypted_info[command_name])
                salt = base64.b64decode(encrypted_info['salt'])
                iv = base64.b64decode(encrypted_info['iv'])
            except Exception as e:
                raise ValueError(f"Ungültige Base64-Kodierung: {str(e)}")

            # Entschlüssele Session Key
            try:
                session_key = self.security.decrypt_asymmetric(encrypted_session_key, private_key)
            except Exception as e:
                raise ValueError(f"Session Key Entschlüsselung fehlgeschlagen: {str(e)}")

            # Leite Schlüssel ab
            derived_key = self.security.derive_key(session_key, salt)

            # Entschlüssele Daten
            try:
                decrypted_padded = self.security.decrypt_symmetric(encrypted_data, derived_key, iv)
                decrypted_data = self.security.unpad_data(decrypted_padded)
                return decrypted_data.decode('utf-8')
            except Exception as e:
                raise ValueError(f"Daten-Entschlüsselung fehlgeschlagen: {str(e)}")

        except Exception as e:
            print(f"Detaillierter Entschlüsselungsfehler: {str(e)}")
            raise

    def receive_command(self):
        """Verarbeitet eingehende Nachrichten"""
        try:
            print("\nNeue Nachricht empfangen...")
            message = self.receiver.read()
            message_dict = json.loads(message)
            data = message_dict['data']
            
            # Validiere die Nachricht
            is_valid, validation_message = self.security.validate_message(data)
            if not is_valid:
                print(f"Nachrichtenvalidierung fehlgeschlagen: {validation_message}")
                return

            # Verifiziere äußeren Hash
            if not self.verify_outer_hash(data, message_dict):
                print("Äußere Hash-Validierung fehlgeschlagen")
                return

            # Entschlüssele den Befehl
            try:
                decrypted_command = self.decrypt_message(data)
            except ValueError as e:
                print(f"Entschlüsselungsfehler: {str(e)}")
                return

            # Verifiziere Befehlshash
            if not self.verify_command_hash(decrypted_command, 
                                          data['original_hash'],
                                          data['original_salt']):
                print("Befehlshash-Validierung fehlgeschlagen")
                return

            # Ausgabe der entschlüsselten Nachricht
            print(f"\nNachricht erfolgreich verarbeitet:")
            print(f"Message ID: {data['message_id']}")
            print(f"Zeitstempel: {data['timestamp']}")
            print(f"Absender: {data['sender_id']}")
            print(f"Version: {data['message_version']}")
            print(f"Befehl: {decrypted_command}")

        except Exception as e:
            print(f"Verarbeitungsfehler: {str(e)}")