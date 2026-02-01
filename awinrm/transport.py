"""
HTTP Transport layer using httpx with asyauth integration.

Supports custom transport for advanced use cases (proxies, custom SSL, etc.)
"""
import ssl
import copy
import base64
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlsplit

import httpx

from awinrm import logger
from awinrm.exceptions import WinRMError, WinRMTransportError
from awinrm.encryption import Encryption

from asyauth.common.credentials import UniCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.credssp import CREDSSPCredential
from asyauth.common.winapi.constants import ISC_REQ

__all__ = ['Transport']


class AsyauthHTTPAuth:
    """
    Custom authentication handler that integrates asyauth with httpx.
    Handles SPNEGO (NTLM/Kerberos) and CredSSP authentication.
    """
    
    def __init__(self, credential: UniCredential, auth_type: str = 'spnego'):
        self.credential = credential
        self.auth_type = auth_type
        self.authobj = None
        self.authenticated = False
        self._seq_number = 0
        
    async def authenticate(self, client: httpx.AsyncClient, endpoint: str, 
                          headers: Dict[str, str]) -> httpx.Response:
        """
        Perform the authentication handshake with the server.
        
        Returns the final authenticated response.
        """
        # Prepare credential for the auth type
        cred = self._prepare_credential()
        
        # Create auth object
        self.authobj = cred.build_context()
        
        # Get domain for SPN
        domain = self._get_domain()
        
        # Determine auth header name based on auth type
        if self.auth_type == 'credssp':
            auth_header_name = 'CredSSP'
        else:
            auth_header_name = 'Negotiate'
        
        authreply = None
        response = None
        
        while True:
            # Build flags
            flags = ISC_REQ.CONNECTION | ISC_REQ.CONFIDENTIALITY | ISC_REQ.INTEGRITY | ISC_REQ.MUTUAL_AUTH
            
            # Get SPN
            host = urlsplit(endpoint).hostname
            target_spn = f'HTTP/{host}@{domain}'
            
            # Get next auth token
            authdata, to_continue, err = await self.authobj.authenticate(
                authreply, spn=target_spn, flags=flags
            )
            
            if err is not None:
                raise WinRMError(f'Authentication failed: {err}')
            
            if not to_continue and response is not None and response.status_code == 200:
                self.authenticated = True
                self._seq_number = self.authobj.get_seq_number()
                return response
            
            # Build auth header
            auth_header = f'{auth_header_name} {base64.b64encode(authdata).decode()}'
            
            # Make request
            req_headers = dict(headers)
            req_headers['Authorization'] = auth_header
            
            response = await client.post(endpoint, headers=req_headers, content=b'')
            
            if not to_continue and response.status_code == 200:
                self.authenticated = True
                self._seq_number = self.authobj.get_seq_number()
                return response
            
            if response.status_code not in (200, 401):
                raise WinRMTransportError('http', response.status_code, response.content)
            
            # Get auth reply from response
            www_auth = response.headers.get('www-authenticate', '')
            
            if auth_header_name in www_auth:
                # Extract the token
                for part in www_auth.split(','):
                    part = part.strip()
                    if part.startswith(auth_header_name):
                        token_b64 = part.replace(f'{auth_header_name} ', '').strip()
                        if token_b64:
                            authreply = base64.b64decode(token_b64)
                        break
            else:
                if not to_continue:
                    self.authenticated = True
                    self._seq_number = self.authobj.get_seq_number()
                    return response
                raise WinRMError(f'No {auth_header_name} header in response')
    
    def _prepare_credential(self):
        """Prepare credential for the specified auth type."""
        cred = self.credential
        
        # Unwrap UniCredential if needed
        if hasattr(cred, 'credential'):
            inner_cred = cred.credential
        else:
            inner_cred = cred
        
        if self.auth_type == 'credssp':
            if isinstance(inner_cred, CREDSSPCredential):
                return inner_cred
            elif isinstance(inner_cred, (NTLMCredential, KerberosCredential)):
                return CREDSSPCredential([inner_cred])
            else:
                return CREDSSPCredential([copy.deepcopy(inner_cred)])
        else:  # spnego
            if isinstance(inner_cred, SPNEGOCredential):
                return inner_cred
            elif isinstance(inner_cred, (NTLMCredential, KerberosCredential)):
                return SPNEGOCredential([inner_cred])
            else:
                return SPNEGOCredential([copy.deepcopy(inner_cred)])
    
    def _get_domain(self) -> str:
        """Extract domain from credential."""
        cred = self.credential
        if hasattr(cred, 'credential'):
            cred = cred.credential
        if hasattr(cred, 'credentials'):
            for c in cred.credentials:
                if hasattr(c, 'domain') and c.domain:
                    return c.domain
        if hasattr(cred, 'domain') and cred.domain:
            return cred.domain
        return 'UNKNOWN'
    
    def get_seq_number(self) -> int:
        """Get the current sequence number for encryption."""
        return self._seq_number
    
    def get_active_credential(self):
        """Get the active credential for encryption type detection."""
        if self.authobj is None:
            return None
        return self.authobj.get_active_credential()
    
    @property
    def selected_authentication_context(self):
        """Get the selected authentication context for GSSAPI access."""
        if self.authobj is None:
            return None
        return self.authobj.selected_authentication_context


class Transport:
    """
    HTTP Transport for WinRM using httpx.
    
    Supports custom httpx transport for advanced use cases.
    """
    
    def __init__(
            self,
            endpoint: str,
            credential: UniCredential,
            authtype: str = 'auto',
            ssl_ctx: Optional[ssl.SSLContext] = None,
            read_timeout_sec: Optional[float] = None,
            proxies: Optional[Dict[str, str]] = None,
            transport: Optional[httpx.AsyncBaseTransport] = None,
            verify: bool = True):
        """
        Initialize transport.
        
        Args:
            endpoint: WinRM endpoint URL
            credential: asyauth credential object
            authtype: Authentication type ('auto', 'spnego', 'credssp')
            ssl_ctx: Optional SSL context for HTTPS
            read_timeout_sec: Read timeout in seconds
            proxies: Proxy configuration dict
            transport: Custom httpx transport (for advanced use cases)
            verify: Whether to verify SSL certificates
        """
        self.endpoint = endpoint
        self.credential = credential
        self.authtype = authtype
        self.ssl_ctx = ssl_ctx
        self.read_timeout_sec = read_timeout_sec
        self.proxies = proxies
        self.custom_transport = transport
        self.verify = verify
        
        self.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'Python WinRM client',
        }
        
        self.client: Optional[httpx.AsyncClient] = None
        self.auth: Optional[AsyauthHTTPAuth] = None
        self.encryption: Optional[Encryption] = None
        self.server_supported_authtypes: Optional[List[str]] = None

    def _build_client(self, with_auth: bool = False) -> httpx.AsyncClient:
        """Build httpx client with optional custom transport."""
        kwargs = {
            'timeout': httpx.Timeout(
                timeout=self.read_timeout_sec or 30.0,
                read=self.read_timeout_sec or 30.0
            ),
            'headers': self.default_headers,
        }
        
        # Handle SSL
        if self.ssl_ctx:
            kwargs['verify'] = self.ssl_ctx
        elif not self.verify:
            kwargs['verify'] = False
        
        # Handle proxies
        if self.proxies:
            kwargs['proxies'] = self.proxies
        
        # Handle custom transport - configure for connection keepalive
        if self.custom_transport:
            kwargs['transport'] = self.custom_transport
        else:
            # Create transport with keepalive settings
            # http2=False ensures HTTP/1.1 which is required for NTLM/Kerberos
            # Use Limits to configure connection keepalive
            limits = httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
                keepalive_expiry=300.0,  # 5 minutes
            )
            kwargs['transport'] = httpx.AsyncHTTPTransport(
                retries=0,
                http2=False,
                limits=limits,
            )
        
        return httpx.AsyncClient(**kwargs)

    async def build_session(self):
        """Build authenticated session."""
        # First, probe for supported auth types
        async with self._build_client() as probe_client:
            response = await probe_client.post(self.endpoint, content=b'')
            
            if response.status_code == 401:
                www_auth = response.headers.get('www-authenticate', '')
                self.server_supported_authtypes = [
                    part.strip().split()[0] 
                    for part in www_auth.split(',')
                ]
                logger.debug(f'Server supported auth types: {self.server_supported_authtypes}')
                
                if self.authtype == 'auto':
                    if 'Negotiate' in self.server_supported_authtypes:
                        self.authtype = 'spnego'
                    elif 'CredSSP' in self.server_supported_authtypes:
                        self.authtype = 'credssp'
                    else:
                        raise WinRMError('No supported authentication types available on the server')
                
                logger.debug(f'Using auth type: {self.authtype}')
                
            elif response.status_code == 200:
                raise WinRMTransportError(
                    'http', response.status_code, 
                    "Server doesn't require authentication. This is unexpected!"
                )
        
        # Create persistent client for authenticated session
        self.client = self._build_client(with_auth=True)
        
        # Create auth handler
        self.auth = AsyauthHTTPAuth(self.credential, self.authtype)
        
        # Perform authentication
        await self.auth.authenticate(self.client, self.endpoint, self.default_headers)
        
        # Setup encryption
        await self.setup_encryption()

    async def setup_encryption(self):
        """Setup message encryption after authentication."""
        self.encryption = Encryption(self.auth, self.authtype)
        self.encryption.sequence_number = self.auth.get_seq_number()

    async def close_session(self):
        """Close the HTTP session."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def send_message(self, message: bytes, _retry: bool = True) -> bytes:
        """Send a message and return the response."""
        if not self.client:
            await self.build_session()
        
        # Store original message for potential retry
        original_message = message
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        headers = dict(self.default_headers)
        
        if self.encryption:
            message, extra_headers = await self.encryption.prepare_encrypted_request(
                self.endpoint, message
            )
            for key, value in extra_headers:
                headers[key] = value
        
        response = await self.client.post(
            self.endpoint, 
            content=message, 
            headers=headers
        )
        
        # Handle 401 - re-authenticate and retry
        if response.status_code == 401 and _retry:
            logger.debug('Got 401, re-authenticating...')
            await self._reauthenticate()
            return await self.send_message(original_message, _retry=False)
        
        if response.status_code != 200:
            errtext = response.content
            if self.encryption:
                try:
                    errtext = await self.encryption.parse_encrypted_response(response, errtext)
                except Exception:
                    pass  # Keep raw error text if decryption fails
            raise WinRMTransportError('http', response.status_code, errtext)
        
        return await self._get_message_response_text(response)
    
    async def _reauthenticate(self):
        """Re-authenticate with the server."""
        # Close existing client
        if self.client:
            await self.client.aclose()
        
        # Create new client
        self.client = self._build_client(with_auth=True)
        
        # Create new auth handler
        self.auth = AsyauthHTTPAuth(self.credential, self.authtype)
        
        # Perform authentication
        await self.auth.authenticate(self.client, self.endpoint, self.default_headers)
        
        # Setup encryption with new auth context
        await self.setup_encryption()
        
        logger.debug('Re-authentication successful')

    async def _get_message_response_text(self, response: httpx.Response) -> bytes:
        """Extract and decrypt response text."""
        data = response.content
        if self.encryption:
            data = await self.encryption.parse_encrypted_response(response, data)
        return data
