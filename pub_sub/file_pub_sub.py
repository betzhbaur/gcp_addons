from pub_sub import Publisher, Subscriber

class FilePublisher(Publisher):
    def __init__(self, file):
        self.file = file

    def write(self, message: str):
        with open(self.file, 'w', encoding='utf-8') as f:
            f.write(message)

class FileSubscriber(Subscriber):
    def __init__(self, file):
        self.file = file

    def read(self):
        with open(self.file, 'r', encoding='utf-8') as f:
            message = f.read()
            return message