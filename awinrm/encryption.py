"""
WinRM Message Encryption/Decryption.

Handles SPNEGO (NTLM/Kerberos) and CredSSP message encryption for WinRM.
"""
import re
import struct
from typing import Tuple, List, Any
from urllib.parse import urlsplit

from awinrm import logger
from awinrm.exceptions import WinRMError

from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential


class Encryption:
    """
    Handles WinRM message encryption and decryption.
    
    Supports SPNEGO (NTLM/Kerberos) and CredSSP protocols.
    """

    SIXTEEN_KB = 16384
    MIME_BOUNDARY = b'--Encrypted Boundary'

    def __init__(self, auth_handler, protocol: str):
        """
        Initialize encryption handler.
        
        [MS-WSMV] v30.0 2016-07-14

        2.2.9.1 Encrypted Message Types
        When using Encryption, there are three options available
            1. Negotiate/SPNEGO
            2. Kerberos
            3. CredSSP

        :param auth_handler: The authentication handler with authobj for encrypt/decrypt
        :param protocol: The auth protocol used ('spnego' or 'credssp')
        """
        self.protocol = protocol.lower()
        self.auth_handler = auth_handler
        self.sequence_number = 0
        
        logger.debug(f'Using encryption protocol: {self.protocol}')
        
        cred = self.auth_handler.get_active_credential()
        
        if self.protocol == 'spnego':
            if isinstance(cred, NTLMCredential):
                self.protocol_string = b"application/HTTP-SPNEGO-session-encrypted"
                self._build_message = self._build_ntlm_message
                self._decrypt_message = self._decrypt_ntlm_message
            elif isinstance(cred, KerberosCredential):
                self.protocol_string = b"application/HTTP-SPNEGO-session-encrypted"
                self._build_message = self._build_kerberos_message
                self._decrypt_message = self._decrypt_kerberos_message
            else:
                raise WinRMError(f"Unsupported credential type for SPNEGO: {type(cred)}")

        elif self.protocol == 'credssp':
            self.protocol_string = b"application/HTTP-CredSSP-session-encrypted"
            self._build_message = self._build_credssp_message
            self._decrypt_message = self._decrypt_credssp_message
            
        else:
            raise WinRMError(f"Encryption for protocol '{self.protocol}' not supported")

    async def prepare_encrypted_request(self, endpoint: str, message: bytes) -> Tuple[bytes, List[Tuple[str, str]]]:
        """
        Create encrypted request with appropriate headers.

        :param endpoint: The WinRM endpoint URL
        :param message: The unencrypted message to send
        :return: Tuple of (encrypted_message, headers)
        """
        host = urlsplit(endpoint).hostname

        if self.protocol == 'credssp' and len(message) > self.SIXTEEN_KB:
            content_type = 'multipart/x-multi-encrypted'
            encrypted_message = b''
            message_chunks = [message[i:i+self.SIXTEEN_KB] for i in range(0, len(message), self.SIXTEEN_KB)]
            for message_chunk in message_chunks:
                encrypted_chunk = await self._encrypt_message(message_chunk, host)
                encrypted_message += encrypted_chunk
        else:
            content_type = 'multipart/encrypted'
            encrypted_message = await self._encrypt_message(message, host)
        
        encrypted_message += self.MIME_BOUNDARY + b"--\r\n"
        
        headers = [
            ('Content-Type', f'{content_type};protocol="{self.protocol_string.decode()}";boundary="Encrypted Boundary"')
        ]

        return encrypted_message, headers

    async def parse_encrypted_response(self, response: Any, data: bytes) -> bytes:
        """
        Decrypt response from server.

        :param response: The HTTP response object (httpx.Response)
        :param data: The encrypted response body
        :return: The decrypted message
        """
        # httpx uses response.headers dict
        content_type = response.headers.get('content-type', '')
        
        if not content_type:
            return data
        
        if f'protocol="{self.protocol_string.decode()}"' in content_type:
            # httpx URL is a URL object, need to get hostname
            host = urlsplit(str(response.url)).hostname
            msg = await self._decrypt_response(host, data)
        else:
            msg = data

        return msg

    async def _encrypt_message(self, message: bytes, host: str) -> bytes:
        """Encrypt a single message chunk."""
        message_length = str(len(message)).encode()
        encrypted_stream = await self._build_message(message, host)

        message_payload = (
            self.MIME_BOUNDARY + b"\r\n"
            b"\tContent-Type: " + self.protocol_string + b"\r\n"
            b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + message_length + b"\r\n" +
            self.MIME_BOUNDARY + b"\r\n"
            b"\tContent-Type: application/octet-stream\r\n" +
            encrypted_stream
        )

        return message_payload

    async def _decrypt_response(self, host: str, data: bytes) -> bytes:
        """Decrypt response containing one or more encrypted chunks."""
        parts = data.split(self.MIME_BOUNDARY + b'\r\n')
        parts = list(filter(None, parts))
        message = b''

        for i in range(0, len(parts)):
            if i % 2 == 1:
                continue

            header = parts[i].strip()
            payload = parts[i + 1]

            expected_length = int(header.split(b'Length=')[1])

            # Remove end MIME block if present
            if payload.endswith(self.MIME_BOUNDARY + b'--\r\n'):
                payload = payload[:len(payload) - 24]

            encrypted_data = payload.replace(b'\tContent-Type: application/octet-stream\r\n', b'')
            decrypted_message = await self._decrypt_message(encrypted_data, host)
            actual_length = len(decrypted_message)

            if actual_length != expected_length:
                raise WinRMError(
                    f'Encrypted length mismatch: expected {expected_length}, got {actual_length}'
                )
            message += decrypted_message

        return message

    async def _decrypt_ntlm_message(self, encrypted_data: bytes, host: str) -> bytes:
        """Decrypt NTLM-encrypted message."""
        message = await self.auth_handler.authobj.decrypt(encrypted_data[4:], None)
        return message[0]

    async def _decrypt_credssp_message(self, encrypted_data: bytes, host: str) -> bytes:
        """Decrypt CredSSP-encrypted message."""
        message, _ = await self.auth_handler.authobj.decrypt(encrypted_data[4:], None)
        return message

    async def _decrypt_kerberos_message(self, encrypted_data: bytes, host: str) -> bytes:
        """
        Decrypt Kerberos-encrypted WinRM message.
        
        WinRM format: sig_len(4) + header(sig_len) + encrypted_data
        For AES (CFX tokens): header + data is passed directly to GSS_Unwrap
        For RC4 (legacy tokens): requires special handling
        """
        sig_len = struct.unpack("<i", encrypted_data[:4])[0]
        header = encrypted_data[4:4 + sig_len]
        data = encrypted_data[4 + sig_len:]
        
        # Check for CFX token ID (0x0504) which indicates AES encryption
        is_cfx = len(header) >= 2 and header[0:2] == b'\x05\x04'
        
        if is_cfx:
            # AES/CFX: combine header + data and pass to GSS_Unwrap
            auth_ctx = self.auth_handler.selected_authentication_context
            gssapi = getattr(auth_ctx, 'gssapi', None)
            
            if gssapi is not None:
                combined = header + data
                message, err = gssapi.GSS_Unwrap(combined, 0, direction='accept')
                if err:
                    raise WinRMError(f'Kerberos decryption failed: {err}')
                return message
        
        # RC4/Legacy token handling
        if sig_len == 24 and len(data) >= 8:
            encrypted_confounder = data[:8]
            encrypted_message = data[8:]
            raw_signature = header + encrypted_confounder
        else:
            raw_signature = header
            encrypted_message = data

        # Re-wrap with GSSAPI OID for decrypt function
        gssapi_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        inner_len = len(gssapi_oid) + len(raw_signature)
        if inner_len < 0x80:
            gssapi_header = b'\x60' + bytes([inner_len]) + gssapi_oid
        else:
            gssapi_header = b'\x60\x81' + bytes([inner_len]) + gssapi_oid
        signature = b'\x00'*8 + gssapi_header + raw_signature

        message, _ = await self.auth_handler.authobj.decrypt(encrypted_message, 0, auth_data=signature)
        return message

    async def _build_ntlm_message(self, message: bytes, host: str) -> bytes:
        """Build NTLM-encrypted message."""
        sealed_message, signature = await self.auth_handler.authobj.encrypt(message, self.sequence_number)
        signature_length = struct.pack("<i", len(signature))
        self.sequence_number += 1
        return signature_length + signature + sealed_message

    async def _build_credssp_message(self, message: bytes, host: str) -> bytes:
        """Build CredSSP-encrypted message."""
        sealed_message, _ = await self.auth_handler.authobj.encrypt(message, self.sequence_number)
        cipher_negotiated = self.auth_handler.authobj.get_cipher_name()
        trailer_length = self._get_credssp_trailer_length(len(message), cipher_negotiated)
        return struct.pack("<i", trailer_length) + sealed_message

    async def _build_kerberos_message(self, message: bytes, host: str) -> bytes:
        """
        Build Kerberos-encrypted WinRM message.
        
        WinRM expects: sig_len(4) + header(60) + encrypted_data
        
        For AES (non-DCE GSSAPI):
            GSS_Wrap returns (cipher, token) where:
            - token: 16-byte CFX header
            - cipher: rotated encrypted data
            Combined format: token(16) + cipher
            WinRM format: first 60 bytes as header, rest as data
        
        For RC4 (legacy tokens):
            Falls back to standard asyauth encrypt method
        """
        auth_ctx = self.auth_handler.selected_authentication_context
        gssapi = getattr(auth_ctx, 'gssapi', None)
        
        # Check if this is AES
        if gssapi is not None and type(gssapi).__name__ == 'GSSAPI_AES':
            cipher, token = gssapi.GSS_Wrap(message, self.sequence_number)
            self.sequence_number += 1
            
            combined = token + cipher
            header = combined[:60]
            data = combined[60:]
            
            sig_len = struct.pack("<i", len(header))
            return sig_len + header + data
        
        # Fallback: standard asyauth encrypt (for RC4)
        sealed_message, signature = await self.auth_handler.authobj.encrypt(message, self.sequence_number)
        self.sequence_number += 1
        
        # Strip GSSAPI OID wrapper
        if signature[0] == 0x60:
            if signature[1] < 0x80:
                offset = 2
            elif signature[1] == 0x81:
                offset = 3
            else:
                offset = 4
            if signature[offset] == 0x06:
                oid_len = signature[offset + 1]
                inner_offset = offset + 2 + oid_len
                signature = signature[inner_offset:]
        
        # RC4 token handling
        if len(signature) == 32:
            header = signature[:24]
            encrypted_confounder = signature[24:32]
            signature_length = struct.pack("<i", len(header))
            return signature_length + header + encrypted_confounder + sealed_message
        
        signature_length = struct.pack("<i", len(signature))
        return signature_length + signature + sealed_message

    def _get_credssp_trailer_length(self, message_length: int, cipher_suite: str) -> int:
        """Calculate CredSSP trailer length based on cipher suite."""
        if re.match(r'^.*-GCM-[\w\d]*$', cipher_suite):
            return 16
        
        hash_algorithm = cipher_suite.split('-')[-1]
        
        if hash_algorithm == 'MD5':
            hash_length = 16
        elif hash_algorithm == 'SHA':
            hash_length = 20
        elif hash_algorithm == 'SHA256':
            hash_length = 32
        elif hash_algorithm == 'SHA384':
            hash_length = 48
        else:
            hash_length = 0

        pre_pad_length = message_length + hash_length

        if "RC4" in cipher_suite:
            padding_length = 0
        elif "DES" in cipher_suite or "3DES" in cipher_suite:
            padding_length = 8 - (pre_pad_length % 8)
        else:
            padding_length = 16 - (pre_pad_length % 16)

        return (pre_pad_length + padding_length) - message_length
