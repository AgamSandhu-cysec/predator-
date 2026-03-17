import abc

class BaseEnumerator(abc.ABC):

    def __init__(self, session, config=None):
        self.session = session
        self.config = config or {}
        self.raw_results = {}
        self.parsed_data = {}

    @abc.abstractmethod
    def run_all(self, update_callback=None):
        """Runs all applicable commands for the platform."""
        pass

    @abc.abstractmethod
    def run_category(self, category: str):
        """Runs commands for a specific category."""
        pass

    @abc.abstractmethod
    def parse_results(self):
        """Parses raw execution results into structured dictionaries."""
        pass

    @abc.abstractmethod
    def extract_features(self):
        """Converts parsed capabilities into a feature vector."""
        pass

    @abc.abstractmethod
    def get_structured_findings(self):
        """Returns structured JSON dictionary of identified vulnerabilities."""
        pass

    @abc.abstractmethod
    def get_features(self):
        """Returns array of numerical features for the ML model."""
        pass
