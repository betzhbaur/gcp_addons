from receiver import SecureReceiver
from sender import SecureSender
from file_pub_sub import FilePublisher, FileSubscriber

# TODOs:
# - Key rotation with key ids
# - Message receiver wrapper
# - Pub/Sub Wrapper implementation for pub_sub.py
# - ECC full implemantaion
# - Wrapper for different cyper implementations
def main():
    # Konfiguration

    command = "START_PROCESS"
    sender = SecureSender(FilePublisher("output.json"))
    sender.send_command(command)

    receiver = SecureReceiver(FileSubscriber("output.json"))
    receiver.receive_command()

if __name__ == "__main__":
    main()