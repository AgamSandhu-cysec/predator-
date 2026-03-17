class MockSession:

    def __init__(self, responses=None):
        """
        Initializes the MockSession.
        :param responses: A dictionary mapping command strings to a tuple
                          (stdout, stderr, exit_code).
        """
        self.responses = responses or {}
        self.called_commands = []
        self.platform = 'Unknown'

    def set_responses(self, responses):
        self.responses = responses

    def run_command(self, command, timeout=30):
        """
        Simulates running a command.
        """
        self.called_commands.append(command)
        if command in self.responses:
            return self.responses[command]
        else:
            return ('', f'bash: {command}: command not found\n', 127)

    def upload_file(self, local_path, remote_path):
        pass

    def download_file(self, remote_path, local_path):
        pass
