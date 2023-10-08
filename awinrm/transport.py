from __future__ import unicode_literals

from awinrm import logger
from awinrm.exceptions import InvalidCredentialsError, WinRMError, WinRMTransportError
from awinrm.encryption import Encryption
from asysocks.unicomm.protocol.client.http.client import ClientSession

DISPLAYED_PROXY_WARNING = False
DISPLAYED_CA_TRUST_WARNING = False

unicode_type = type(u'')

__all__ = ['Transport']


def strtobool(value):
    value = value.lower()
    if value in ('true', 't', 'yes', 'y', 'on', '1'):
        return True

    elif value in ('false', 'f', 'no', 'n', 'off', '0'):
        return False

    else:
        raise ValueError("invalid truth value '%s'" % value)


class UnsupportedAuthArgument(Warning):
    pass


class Transport(object):
    def __init__(
            self, 
            endpoint, 
            credential,
            authtype='auto',
            ssl_ctx=None,
            read_timeout_sec=None,
            proxies=None):
        self.credential = credential
        self.ssl_ctx = ssl_ctx
        self.endpoint = endpoint
        self.read_timeout_sec = read_timeout_sec
        self.authtype = authtype
        self.server_supported_authtypes = None
        self.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'Python WinRM client',
        }
        self.proxies = proxies

        self.session = None
        self.encryption = None

    async def build_session(self):
        async with ClientSession(proxies = self.proxies) as session:
            session.static_headers.update(self.default_headers)
            async with session.post(self.endpoint, data=None) as response:
                respdata = await response.read()
                if response.status == 401:
                    self.server_supported_authtypes = response.get_all('www-authenticate', [])
                    logger.debug('Server supported auth types: %s' % self.server_supported_authtypes)
                    if self.authtype == 'auto':
                        if 'Negotiate' in self.server_supported_authtypes:
                            self.authtype = 'spnego'
                        elif 'CredSSP' in self.server_supported_authtypes:
                            self.authtype = 'credssp'
                        else:
                            raise WinRMError('No supported authentication types available on the server')
                    logger.debug('Using auth type: %s' % self.authtype)

                elif response.status == 200:
                    raise WinRMTransportError('http', response.status, 'Server doesn\'t require authentication. This is unexpected!')
                
        session = ClientSession(credential=self.credential, ssl_ctx=self.ssl_ctx, force_sinle_connection=True, auth_type=self.authtype,proxies = self.proxies)
        session.static_headers.update(self.default_headers)
        self.session = session
        await self.setup_encryption()

    async def setup_encryption(self):
        try:
            # Security context doesn't exist, sending blank message to initialise context
            async with self.session.post(self.endpoint, data=None) as response:
                if response.status != 200:
                    respdata = await response.read()
                    raise WinRMTransportError('http', response.status, respdata)
            
            self.encryption = Encryption(self.session, self.authtype)
            self.encryption.sequence_number = self.session.authmanager.authobj.get_seq_number()
        except Exception as e:
            raise e

    async def close_session(self):
        if not self.session:
            return
        await self.session.close()
        self.session = None

    async def send_message(self, message):
        if not self.session:
            await self.build_session()

        # urllib3 fails on SSL retries with unicode buffers- must send it a byte string
        # see https://github.com/shazow/urllib3/issues/717
        if isinstance(message, unicode_type):
            message = message.encode('utf-8')

        headers = []
        if self.encryption:
            message, headers = await self.encryption.prepare_encrypted_request(self.endpoint, message)

        try:
            async with self.session.post(self.endpoint, data=message, headers=headers) as response:
                if response.status != 200:
                    errtext = await response.read()
                    if self.encryption:
                        errtext = await self.encryption.parse_encrypted_response(response, errtext)
                    raise WinRMTransportError('http', response.status, errtext)

                data = await response.read()
                return await self._get_message_response_text(response, data)
        except Exception as e:
            raise e

    async def _get_message_response_text(self, response, data):
        if self.encryption:
            response_text = await self.encryption.parse_encrypted_response(response, data)
        else:
            response_text = data
        return response_text