from abc import ABC, abstractmethod

class BaseConnector(ABC):
    """Abstract base class for all connectors."""

    def __init__(self, host, username, password=None, keyfile=None):
        self.host = host
        self.username = username
        self.password = password
        self.keyfile = keyfile
        self.session = None
        self.connected = False

    @abstractmethod
    def connect(self):
        """Establish the connection. Returns True on success, False otherwise."""
        pass

    @abstractmethod
    def run_command(self, command):
        """Execute a command and return (stdout, stderr)."""
        pass

    @abstractmethod
    def upload_file(self, local_path, remote_path):
        """Upload a file to the remote system."""
        pass

    @abstractmethod
    def interactive_session(self):
        """Drop into an interactive shell."""
        pass
