"""
awinrm - Asynchronous Python library for Windows Remote Management

Provides async WinRM client functionality using httpx for HTTP transport
and asyauth for authentication (SPNEGO/NTLM/Kerberos/CredSSP).
"""
import logging

# Setup logger first to avoid circular import issues
logger = logging.getLogger('awinrm')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# Silence httpx and httpcore loggers - they're too chatty
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)

import re
import ssl
import asyncio
import warnings
from base64 import b64encode
from typing import Optional, Dict, Any, Tuple, AsyncIterator
import xml.etree.ElementTree as ET

import httpx

from asyauth.common.credentials import UniCredential
from awinrm.protocol import Protocol
from awinrm.exceptions import (
    ShellTerminatedError, 
    ShellNotFoundError, 
    WinRMError,
    WinRMTransportError,
    WinRMOperationTimeoutError,
    AuthenticationError,
)

# Re-export exceptions for easy import
__all__ = [
    'Session',
    'WinRMShell', 
    'decode_bytes',
    'ShellTerminatedError',
    'ShellNotFoundError',
    'WinRMError',
    'WinRMTransportError',
    'WinRMOperationTimeoutError',
    'AuthenticationError',
    'logger',
]


class Session:
    """
    WinRM Session for executing commands on remote Windows hosts.
    
    Supports SPNEGO (NTLM/Kerberos) and CredSSP authentication.
    """
    
    def __init__(
            self, 
            url: str = None,
            ssl_ctx: Optional[ssl.SSLContext] = None,
            authtype: str = 'auto',
            credential: Optional[UniCredential] = None,
            transport: Optional[httpx.AsyncBaseTransport] = None,
            verify: bool = True,
            timeout: Optional[float] = None,
            proxies: Optional[Dict[str, str]] = None,
            **kwargs):
        """
        Initialize WinRM session.
        
        Args:
            url: WinRM connection URL (e.g., 'http+ntlm-password://user:pass@host')
            ssl_ctx: Optional SSL context for HTTPS connections
            authtype: Authentication type ('auto', 'spnego', 'credssp')
            credential: Optional pre-built UniCredential (if not using URL)
            transport: Optional custom httpx transport for advanced use cases
            verify: Whether to verify SSL certificates (default: True)
            timeout: Request timeout in seconds
            proxies: Proxy configuration dict
            **kwargs: Additional arguments passed to Protocol
        """
        if url is None and credential is None:
            raise ValueError('Either url or credential parameter is required')
        
        if credential is None:
            credential = UniCredential.from_url(url)
        
        # Build endpoint URL
        self.url = self._build_url(url, kwargs.get('transport_type', 'plaintext'))
        
        self.protocol = Protocol(
            self.url, 
            credential,
            ssl_ctx=ssl_ctx,
            authtype=authtype,
            http_transport=transport,
            verify=verify,
            read_timeout_sec=timeout,
            proxies=proxies,
            **kwargs
        )
        self.__shells = []

    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        for shell in self.__shells:
            await shell.close()
        await self.protocol.close()

    def create_shell(
            self, 
            working_directory: str = None, 
            env_vars: Dict[str, str] = None, 
            noprofile: bool = False,
            codepage: int = 437, 
            lifetime: int = None, 
            idle_timeout: int = None,
            keepalive_interval: int = None,
            shell_type: str = 'cmd') -> 'WinRMShell':
        """
        Create an interactive shell.
        
        Args:
            working_directory: Working directory for the shell
            env_vars: Environment variables to set
            noprofile: Skip loading user profile
            codepage: Shell codepage (default: 437)
            lifetime: Shell lifetime in seconds
            idle_timeout: Shell idle timeout
            keepalive_interval: Keepalive interval in seconds (default: 60, 0 to disable)
            shell_type: Shell type - 'cmd', 'powershell', or 'pwsh' (PowerShell Core)
            
        Returns:
            WinRMShell object
        """
        shell = WinRMShell(
            self, 
            working_directory=working_directory, 
            env_vars=env_vars, 
            noprofile=noprofile,
            codepage=codepage, 
            lifetime=lifetime, 
            idle_timeout=idle_timeout,
            keepalive_interval=keepalive_interval,
            shell_type=shell_type
        )
        self.__shells.append(shell)
        return shell

    def create_powershell(
            self,
            working_directory: str = None,
            env_vars: Dict[str, str] = None,
            lifetime: int = None,
            idle_timeout: int = None,
            keepalive_interval: int = None) -> 'WinRMShell':
        """
        Create an interactive PowerShell session.
        
        Convenience method for create_shell(shell_type='powershell').
        
        Args:
            working_directory: Working directory for the shell
            env_vars: Environment variables to set
            lifetime: Shell lifetime in seconds
            idle_timeout: Shell idle timeout
            keepalive_interval: Keepalive interval in seconds (default: 60, 0 to disable)
            
        Returns:
            WinRMShell object configured for PowerShell
        """
        return self.create_shell(
            working_directory=working_directory,
            env_vars=env_vars,
            noprofile=True,  # PowerShell uses -NoProfile flag instead
            lifetime=lifetime,
            idle_timeout=idle_timeout,
            keepalive_interval=keepalive_interval,
            shell_type='powershell'
        )

    async def run_cmd(self, command: str, args: Tuple = ()) -> Tuple[bytes, bytes, int]:
        """
        Execute a command and return output.
        
        Args:
            command: Command to execute
            args: Command arguments
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        shell_id = await self.protocol.open_shell()
        command_id = await self.protocol.run_command(shell_id, command, args)
        
        stdout_buff = b''
        stderr_buff = b''
        return_code = -1
        
        async for stdout, stderr, rc in self.protocol.get_command_output(shell_id, command_id):
            stdout_buff += stdout
            stderr_buff += stderr
            return_code = rc
        
        await self.protocol.cleanup_command(shell_id, command_id)
        await self.protocol.close_shell(shell_id)
        
        return stdout_buff, stderr_buff, return_code

    async def run_ps(self, script: str) -> Tuple[bytes, bytes, int]:
        """
        Execute a PowerShell script.
        
        Args:
            script: PowerShell script to execute
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
        return await self.run_cmd(f'powershell -encodedcommand {encoded_ps}')

    # File transfer chunk size (base64 encoded, so actual bytes = 3/4 of this)
    FILE_TRANSFER_CHUNK_SIZE = 2048  # ~1.5KB actual data per chunk

    async def upload_file(
            self, 
            local_path: str, 
            remote_path: str,
            progress_callback: callable = None) -> None:
        """
        Upload a file to the remote host.
        
        Uses base64 encoding via PowerShell to transfer file contents.
        
        Args:
            local_path: Path to local file
            remote_path: Destination path on remote host (e.g., 'C:\\temp\\file.txt')
            progress_callback: Optional callback(bytes_sent, total_bytes) for progress
            
        Raises:
            FileNotFoundError: If local file doesn't exist
            WinRMError: If upload fails
        """
        import os
        from awinrm.exceptions import WinRMError
        
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")
        
        file_size = os.path.getsize(local_path)
        bytes_sent = 0
        
        # Read file and encode as base64
        with open(local_path, 'rb') as f:
            file_data = f.read()
        
        # For small files, send in one chunk
        if file_size <= self.FILE_TRANSFER_CHUNK_SIZE:
            encoded = b64encode(file_data).decode('ascii')
            script = f'''
$bytes = [Convert]::FromBase64String("{encoded}")
[IO.File]::WriteAllBytes("{remote_path}", $bytes)
Write-Host "OK"
'''
            stdout, stderr, rc = await self.run_ps(script)
            if rc != 0 or b'OK' not in stdout:
                raise WinRMError(f"Upload failed: {stderr.decode('utf-8', errors='replace')}")
            
            if progress_callback:
                progress_callback(file_size, file_size)
            return
        
        # For larger files, send in chunks
        # First, create empty file
        script = f'''
if (Test-Path "{remote_path}") {{ Remove-Item "{remote_path}" -Force }}
New-Item -Path "{remote_path}" -ItemType File -Force | Out-Null
Write-Host "OK"
'''
        stdout, stderr, rc = await self.run_ps(script)
        if rc != 0 or b'OK' not in stdout:
            raise WinRMError(f"Failed to create remote file: {stderr.decode('utf-8', errors='replace')}")
        
        # Send chunks
        chunk_size = int(self.FILE_TRANSFER_CHUNK_SIZE * 3 / 4)  # Account for base64 expansion
        
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            encoded = b64encode(chunk).decode('ascii')
            
            script = f'''
$bytes = [Convert]::FromBase64String("{encoded}")
$stream = [IO.File]::Open("{remote_path}", [IO.FileMode]::Append)
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
Write-Host "OK"
'''
            stdout, stderr, rc = await self.run_ps(script)
            if rc != 0 or b'OK' not in stdout:
                raise WinRMError(f"Upload chunk failed: {stderr.decode('utf-8', errors='replace')}")
            
            bytes_sent += len(chunk)
            if progress_callback:
                progress_callback(bytes_sent, file_size)

    async def download_file(
            self,
            remote_path: str,
            local_path: str,
            progress_callback: callable = None) -> None:
        """
        Download a file from the remote host.
        
        Uses base64 encoding via PowerShell to transfer file contents.
        
        Args:
            remote_path: Path to file on remote host (e.g., 'C:\\temp\\file.txt')
            local_path: Destination path on local host
            progress_callback: Optional callback(bytes_received, total_bytes) for progress
            
        Raises:
            FileNotFoundError: If remote file doesn't exist
            WinRMError: If download fails
        """
        import os
        from awinrm.exceptions import WinRMError
        
        # Get file size first
        script = f'''
if (Test-Path "{remote_path}") {{
    (Get-Item "{remote_path}").Length
}} else {{
    Write-Error "File not found"
    exit 1
}}
'''
        stdout, stderr, rc = await self.run_ps(script)
        if rc != 0:
            raise FileNotFoundError(f"Remote file not found: {remote_path}")
        
        try:
            file_size = int(stdout.decode().strip())
        except ValueError:
            raise WinRMError(f"Failed to get file size: {stdout.decode()}")
        
        # For small files, download in one chunk
        chunk_size = int(self.FILE_TRANSFER_CHUNK_SIZE * 3 / 4)
        
        if file_size <= chunk_size:
            script = f'''
$bytes = [IO.File]::ReadAllBytes("{remote_path}")
[Convert]::ToBase64String($bytes)
'''
            stdout, stderr, rc = await self.run_ps(script)
            if rc != 0:
                raise WinRMError(f"Download failed: {stderr.decode('utf-8', errors='replace')}")
            
            # Decode and write
            from base64 import b64decode
            file_data = b64decode(stdout.decode().strip())
            
            os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
            with open(local_path, 'wb') as f:
                f.write(file_data)
            
            if progress_callback:
                progress_callback(file_size, file_size)
            return
        
        # For larger files, download in chunks
        from base64 import b64decode
        
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        bytes_received = 0
        
        with open(local_path, 'wb') as f:
            offset = 0
            while offset < file_size:
                script = f'''
$stream = [IO.File]::OpenRead("{remote_path}")
$stream.Seek({offset}, [IO.SeekOrigin]::Begin) | Out-Null
$buffer = New-Object byte[] {chunk_size}
$read = $stream.Read($buffer, 0, {chunk_size})
$stream.Close()
if ($read -gt 0) {{
    [Convert]::ToBase64String($buffer[0..($read-1)])
}}
'''
                stdout, stderr, rc = await self.run_ps(script)
                if rc != 0:
                    raise WinRMError(f"Download chunk failed: {stderr.decode('utf-8', errors='replace')}")
                
                chunk_b64 = stdout.decode().strip()
                if not chunk_b64:
                    break
                
                chunk_data = b64decode(chunk_b64)
                f.write(chunk_data)
                
                bytes_received += len(chunk_data)
                offset += len(chunk_data)
                
                if progress_callback:
                    progress_callback(bytes_received, file_size)

    async def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists on the remote host."""
        script = f'if (Test-Path "{remote_path}") {{ "true" }} else {{ "false" }}'
        stdout, stderr, rc = await self.run_ps(script)
        return b'true' in stdout

    async def get_file_size(self, remote_path: str) -> int:
        """Get the size of a file on the remote host."""
        script = f'(Get-Item "{remote_path}").Length'
        stdout, stderr, rc = await self.run_ps(script)
        if rc != 0:
            raise FileNotFoundError(f"Remote file not found: {remote_path}")
        return int(stdout.decode().strip())

    def _clean_error_msg(self, msg: bytes) -> bytes:
        """Convert PowerShell CLIXML error message to readable string."""
        if msg.startswith(b"#< CLIXML\r\n"):
            msg_xml = msg[11:]
            try:
                msg_xml = self._strip_namespace(msg_xml)
                root = ET.fromstring(msg_xml)
                nodes = root.findall("./S")
                new_msg = ""
                for s in nodes:
                    new_msg += s.text.replace("_x000D__x000A_", "\n")
            except Exception as e:
                warnings.warn(f"Problem converting PowerShell error: {e}")
            else:
                if new_msg:
                    return new_msg.strip().encode('utf-8')
        return msg

    def _strip_namespace(self, xml: bytes) -> bytes:
        """Strip namespaces from XML."""
        p = re.compile(b"xmlns=*[\"\"][^\"\"]*[\"\"]")
        for match in p.finditer(xml):
            xml = xml.replace(match.group(), b"")
        return xml

    @staticmethod
    def _build_url(target: str, transport_type: str) -> str:
        """Build WinRM endpoint URL from target."""
        if target is None:
            raise ValueError("URL is required")
        
        # Extract host/port from URL, ignoring auth parts and query params
        # Pattern: [scheme://][user@]host[:port][/path][?query]
        match = re.match(
            r'(?i)^(?:[^:]+://)?(?:[^@]+@)?(?P<host>[0-9a-z-_.]+)(:(?P<port>\d+))?(?P<path>/[^?]*)?',
            target
        )
        
        if not match:
            raise ValueError(f"Invalid URL: {target}")
        
        host = match.group('host')
        port = match.group('port')
        path = match.group('path')
        
        scheme = 'https' if transport_type == 'ssl' else 'http'
        if not port:
            port = 5986 if transport_type == 'ssl' else 5985
        if not path or path == '/':
            path = '/wsman'
        
        return f'{scheme}://{host}:{port}{path}'


class WinRMShell:
    """Interactive WinRM shell session with keepalive support."""
    
    DEFAULT_KEEPALIVE_INTERVAL = 60  # seconds
    
    # Shell types
    SHELL_CMD = 'cmd.exe'
    SHELL_POWERSHELL = 'powershell.exe -NoLogo -NoProfile -NonInteractive'
    SHELL_PWSH = 'pwsh.exe -NoLogo -NoProfile -NonInteractive'  # PowerShell Core
    
    def __init__(
            self, 
            session: Session,
            working_directory: str = None,
            env_vars: Dict[str, str] = None,
            noprofile: bool = False,
            codepage: int = 437,
            lifetime: int = None,
            idle_timeout: int = None,
            keepalive_interval: int = None,
            shell_type: str = 'cmd'):
        """
        Initialize WinRM shell.
        
        Args:
            session: Parent Session object
            working_directory: Working directory for shell
            env_vars: Environment variables
            noprofile: Skip loading user profile
            codepage: Shell codepage
            lifetime: Shell lifetime in seconds
            idle_timeout: Shell idle timeout (WinRM server setting)
            keepalive_interval: Keepalive interval in seconds (default: 60, 0 to disable)
            shell_type: Shell type - 'cmd', 'powershell', or 'pwsh' (PowerShell Core)
        """
        self.session = session
        self.working_directory = working_directory
        self.env_vars = env_vars
        self.noprofile = noprofile
        self.codepage = codepage
        self.lifetime = lifetime
        self.idle_timeout = idle_timeout
        self.shell_type = shell_type
        
        # Set shell command based on type
        if shell_type == 'powershell':
            self.shell_cmd = self.SHELL_POWERSHELL
        elif shell_type == 'pwsh':
            self.shell_cmd = self.SHELL_PWSH
        else:
            self.shell_cmd = self.SHELL_CMD
        
        self.command_id = None
        self.closed_evt = asyncio.Event()
        
        # Keepalive settings
        if keepalive_interval is None:
            keepalive_interval = self.DEFAULT_KEEPALIVE_INTERVAL
        self.keepalive_interval = keepalive_interval
        self._keepalive_task: Optional[asyncio.Task] = None
        self._last_activity = 0.0

        self.shell_id = None
        self.stdin = asyncio.Queue()
        self.stdout = asyncio.Queue()
        self.stderr = asyncio.Queue()
        self.return_code = None
        
        # Track if the shell/command has terminated
        self._command_done = False
        self._terminated_evt = asyncio.Event()

    @property
    def is_terminated(self) -> bool:
        """Check if the shell has terminated."""
        return self._terminated_evt.is_set()
    
    def _set_terminated(self, exit_code: int = 0):
        """Mark the shell as terminated."""
        self._command_done = True
        self.return_code = exit_code
        self._terminated_evt.set()
        self.closed_evt.set()  # Also stop keepalive

    async def __aenter__(self):
        try:
            self.shell_id = await self.session.protocol.open_shell(
                working_directory=self.working_directory,
                env_vars=self.env_vars,
                noprofile=self.noprofile,
                codepage=self.codepage,
                lifetime=self.lifetime,
                idle_timeout=self.idle_timeout
            )
            self.command_id = await self.session.protocol.run_command(self.shell_id, self.shell_cmd)
            stdout, stderr, return_code, command_done = await self.session.protocol._raw_get_command_output(
                self.shell_id, self.command_id
            )
            await self.stdout.put(stdout)
            await self.stderr.put(stderr)
            self.return_code = return_code
            
            # Check if command completed immediately (unlikely for shells, but possible)
            if command_done:
                self._set_terminated(return_code)
            
            # Start keepalive if enabled and shell is still running
            if self.keepalive_interval > 0 and not self.is_terminated:
                self._start_keepalive()
            
            return self
        except Exception as e:
            await self.__aexit__(None, None, None)
            raise e
    
    async def wait_for_termination(self) -> int:
        """
        Wait for the shell to terminate.
        
        Returns:
            The exit code of the shell
        """
        await self._terminated_evt.wait()
        return self.return_code or 0
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    def _start_keepalive(self):
        """Start the keepalive background task."""
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())
            self._update_activity()

    def _stop_keepalive(self):
        """Stop the keepalive background task."""
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            self._keepalive_task = None

    def _update_activity(self):
        """Update last activity timestamp."""
        import time
        self._last_activity = time.monotonic()

    async def _keepalive_loop(self):
        """Background task that sends keepalive requests."""
        import time
        
        logger.debug(f'Keepalive started with interval {self.keepalive_interval}s')
        
        while not self.closed_evt.is_set():
            try:
                await asyncio.sleep(self.keepalive_interval)
                
                if self.closed_evt.is_set():
                    break
                
                # Check if we need to send keepalive
                elapsed = time.monotonic() - self._last_activity
                if elapsed >= self.keepalive_interval:
                    logger.debug('Sending keepalive ping...')
                    try:
                        # Send a lightweight HTTP request to keep connection alive
                        # Just send an empty encrypted message that the server will reject
                        # but it keeps the HTTP connection and auth context alive
                        await self._send_keepalive_ping()
                    except Exception as e:
                        logger.debug(f'Keepalive ping: {e}')
                    self._update_activity()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f'Keepalive loop error: {e}')
        
        logger.debug('Keepalive stopped')
    
    async def _send_keepalive_ping(self):
        """Send a lightweight keepalive request using unencrypted HTTP."""
        transport = self.session.protocol.transport
        
        if not transport.client:
            return
        
        # Send a simple HTTP request to keep the connection alive
        # Use an unauthenticated request - it will get 401 but keeps TCP alive
        try:
            response = await transport.client.post(
                transport.endpoint,
                content=b'',  # Empty body
                headers={'Content-Type': 'application/soap+xml;charset=UTF-8'}
            )
            logger.debug(f'Keepalive ping response: {response.status_code}')
        except Exception as e:
            logger.debug(f'Keepalive ping error: {e}')

    async def close(self):
        """Close the shell gracefully."""
        if self.closed_evt.is_set():
            return
        
        # Stop keepalive first
        self._stop_keepalive()
        self.closed_evt.set()
        
        # Only try to clean up if we have valid shell/command IDs
        if self.shell_id and self.command_id:
            try:
                await self.session.protocol.cleanup_command(self.shell_id, self.command_id)
                await self.session.protocol.close_shell(self.shell_id)
            except (ShellNotFoundError, ShellTerminatedError):
                # Shell already gone - this is fine
                logger.debug('Shell was already closed on server')
            except Exception as e:
                logger.debug(f'Error closing shell: {e}')

    async def send_input(self, data: bytes):
        """
        Send input to the shell.
        
        Raises:
            ShellTerminatedError: If the shell has already terminated
            ShellNotFoundError: If the shell no longer exists on the server
        """
        if self.is_terminated:
            raise ShellTerminatedError("Shell has already terminated", self.return_code or 0)
        
        self._update_activity()
        try:
            await self.session.protocol.send_command_input(self.shell_id, self.command_id, data)
            await self.read_output()
        except ShellNotFoundError:
            self._set_terminated(-1)
            raise ShellTerminatedError("Shell session was closed by the server", -1)

    async def read_output(self):
        """
        Read output from the shell.
        
        Raises:
            ShellTerminatedError: If the shell has terminated
            ShellNotFoundError: If the shell no longer exists on the server
        """
        if self.is_terminated:
            raise ShellTerminatedError("Shell has already terminated", self.return_code or 0)
        
        self._update_activity()
        try:
            stdout, stderr, return_code, command_done = await self.session.protocol._raw_get_command_output(
                self.shell_id, self.command_id
            )
            await self.stdout.put(stdout)
            await self.stderr.put(stderr)
            self.return_code = return_code
            
            # Check if the command has completed (shell exited)
            if command_done:
                self._set_terminated(return_code)
                raise ShellTerminatedError("Shell session ended", return_code)
                
        except ShellNotFoundError:
            self._set_terminated(-1)
            raise ShellTerminatedError("Shell session was closed by the server", -1)


def decode_bytes(data: bytes, hint: str = 'cp437') -> str:
    """Decode bytes with multiple encoding fallbacks."""
    encodings = ['utf-8', 'cp1252', 'cp1251', 'cp932', 'cp936']
    if hint:
        encodings.insert(0, hint)
    for encoding in encodings:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("Unable to decode with available encodings")
