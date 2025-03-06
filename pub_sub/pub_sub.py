from abc import ABC, abstractmethod

class Publisher(ABC):
    @abstractmethod
    def write(self, message: str):
        pass

class Subscriber(ABC):
    @abstractmethod
    def read(self):
        pass