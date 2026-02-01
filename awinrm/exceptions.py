
class WinRMError(Exception):
    """"Generic WinRM error"""
    code = 500


class WinRMTransportError(Exception):
    """WinRM errors specific to transport-level problems (unexpected HTTP error codes, etc)"""

    @property
    def protocol(self):
        return self.args[0]

    @property
    def code(self):
        return self.args[1]

    @property
    def message(self):
        return 'Bad HTTP response returned from server. Code {0}'.format(self.code)

    @property
    def response_text(self):
        return self.args[2]

    def __str__(self):
        return self.message


class WinRMOperationTimeoutError(Exception):
    """
    Raised when a WinRM-level operation timeout (not a connection-level timeout) has occurred. This is
    considered a normal error that should be retried transparently by the client when waiting for output from
    a long-running process.
    """
    code = 500


class ShellTerminatedError(WinRMError):
    """
    Raised when the remote shell has terminated (user typed 'exit', process ended, or server closed session).
    This is a clean exit condition, not an error in the traditional sense.
    """
    code = 0
    
    def __init__(self, message: str = "Shell session has terminated", exit_code: int = 0):
        self.exit_code = exit_code
        super().__init__(message)
    
    def __str__(self):
        return f"Shell terminated (exit code: {self.exit_code})"


class ShellNotFoundError(WinRMError):
    """
    Raised when trying to interact with a shell that no longer exists on the server.
    Common WSMan fault codes: 2150858843 (shell not found), 2150858880 (invalid shell id)
    """
    code = 404
    
    def __init__(self, shell_id: str = None, message: str = None):
        self.shell_id = shell_id
        if message is None:
            message = f"Shell '{shell_id}' not found or has been closed" if shell_id else "Shell not found or has been closed"
        super().__init__(message)


class AuthenticationError(WinRMError):
    """Authorization Error"""
    code = 401


class BasicAuthDisabledError(AuthenticationError):
    message = 'WinRM/HTTP Basic authentication is not enabled on remote host'


class InvalidCredentialsError(AuthenticationError):
    pass