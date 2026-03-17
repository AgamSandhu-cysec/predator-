class EnumeratorError(Exception):
    """Base exception for enumerator errors."""
    pass

class CommandLoadError(EnumeratorError):
    """Raised when the command dataset cannot be loaded or parsed."""
    pass

class SessionExecError(EnumeratorError):
    """Raised when a command fails to execute on the remote session."""
    pass

class ParsingError(EnumeratorError):
    """Raised when command output cannot be parsed into structured data."""
    pass
