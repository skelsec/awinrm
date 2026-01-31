import re
import struct
from awinrm import logger
from awinrm.exceptions import WinRMError
from urllib.parse import urlsplit

from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.credssp import CREDSSPCredential

# Import IOV patch for Kerberos AES support
try:
    from awinrm.asyauth_iov_patch import patch_gssapi_aes
    patch_gssapi_aes()
except ImportError:
    pass  # Patch not available, will use fallback

class Encryption(object):

    SIXTEN_KB = 16384
    MIME_BOUNDARY = b'--Encrypted Boundary'

    def __init__(self, session, protocol:str):
        """
        [MS-WSMV] v30.0 2016-07-14

        2.2.9.1 Encrypted Message Types
        When using Encryption, there are three options available
            1. Negotiate/SPNEGO
            2. Kerberos
            3. CredSSP
        Details for each implementation can be found in this document under this section

        This init sets the following values to use to encrypt and decrypt. This is to help generify
        the methods used in the body of the class.
            wrap: A method that will return the encrypted message and a signature
            unwrap: A method that will return an unencrypted message and verify the signature
            protocol_string: The protocol string used for the particular auth protocol

        :param session: The handle of the session to get GSS-API wrap and unwrap methods
        :param protocol: The auth protocol used, will determine the wrapping and unwrapping method plus
                         the protocol string to use. Currently only NTLM and CredSSP is supported
        """
        self.protocol = protocol.lower()
        self.session = session
        self.sequence_number = 0
        logger.debug('Using encryption protocol: %s' % self.protocol)
        cred = self.session.authmanager.authobj.get_active_credential()
        if self.protocol == 'spnego':  # Details under Negotiate [2.2.9.1.1] in MS-WSMV
            if isinstance(cred, NTLMCredential):
                self.protocol_string = b"application/HTTP-SPNEGO-session-encrypted"
                self._build_message = self._build_ntlm_message
                self._decrypt_message = self._decrypt_ntlm_message
            elif isinstance(cred, KerberosCredential):
                # For Kerberos over SPNEGO, still use SPNEGO protocol string
                self.protocol_string = b"application/HTTP-SPNEGO-session-encrypted"
                self._build_message = self._build_kerberos_message
                self._decrypt_message = self._decrypt_kerberos_message

        elif self.protocol == 'credssp':  # Details under CredSSP [2.2.9.1.3] in MS-WSMV
            self.protocol_string = b"application/HTTP-CredSSP-session-encrypted"
            self._build_message = self._build_credssp_message
            self._decrypt_message = self._decrypt_credssp_message
            
        else:
            raise WinRMError("Encryption for protocol '%s' not supported in awinrm" % self.protocol)

    async def prepare_encrypted_request(self, endpoint, message):
        """
        Creates a prepared request to send to the server with an encrypted message
        and correct headers

        :param endpoint: The endpoint/server to prepare requests to
        :param message: The unencrypted message to send to the server
        :return: A prepared request that has an encrypted message
        """
        host = urlsplit(endpoint).hostname

        if self.protocol == 'credssp' and len(message) > self.SIXTEN_KB:
            content_type = 'multipart/x-multi-encrypted'
            encrypted_message = b''
            message_chunks = [message[i:i+self.SIXTEN_KB] for i in range(0, len(message), self.SIXTEN_KB)]
            for message_chunk in message_chunks:
                encrypted_chunk = await self._encrypt_message(message_chunk, host)
                encrypted_message += encrypted_chunk
        else:
            content_type = 'multipart/encrypted'
            encrypted_message = await self._encrypt_message(message, host)
        encrypted_message += self.MIME_BOUNDARY + b"--\r\n"
        
        headers = []
        headers.append(('Content-Type', '{0};protocol="{1}";boundary="Encrypted Boundary"'\
            .format(content_type, self.protocol_string.decode())))

        return encrypted_message, headers

    async def parse_encrypted_response(self, response, data):
        """
        Takes in the encrypted response from the server and decrypts it

        :param response: The response that needs to be decrypted
        :return: The unencrypted message from the server
        """
        
        content_type = response.getheaders('content-type')
        if content_type is None:
            return data
        content_type = content_type[0]
        if 'protocol="{0}"'.format(self.protocol_string.decode()) in content_type:
            host = urlsplit(response.url).hostname
            msg = await self._decrypt_response(host, data)
        else:
            msg = data

        return msg

    async def _encrypt_message(self, message, host):
        message_length = str(len(message)).encode()
        encrypted_stream = await self._build_message(message, host)

        message_payload = self.MIME_BOUNDARY + b"\r\n" \
                                               b"\tContent-Type: " + self.protocol_string + b"\r\n" \
                                               b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + message_length + b"\r\n" + \
                                               self.MIME_BOUNDARY + b"\r\n" \
                                               b"\tContent-Type: application/octet-stream\r\n" + \
                                               encrypted_stream

        return message_payload

    async def _decrypt_response(self, host, data):
        parts = data.split(self.MIME_BOUNDARY + b'\r\n')
        parts = list(filter(None, parts))  # filter out empty parts of the split
        message = b''

        for i in range(0, len(parts)):
            if i % 2 == 1:
                continue

            header = parts[i].strip()
            payload = parts[i + 1]

            expected_length = int(header.split(b'Length=')[1])

            # remove the end MIME block if it exists
            if payload.endswith(self.MIME_BOUNDARY + b'--\r\n'):
                payload = payload[:len(payload) - 24]

            encrypted_data = payload.replace(b'\tContent-Type: application/octet-stream\r\n', b'')
            decrypted_message = await self._decrypt_message(encrypted_data, host)
            actual_length = len(decrypted_message)

            if actual_length != expected_length:
                raise WinRMError('Encrypted length from server does not match the '
                                 'expected size, message has been tampered with')
            message += decrypted_message

        return message

    async def _decrypt_ntlm_message(self, encrypted_data, host):
        message = await self.session.authmanager.authobj.decrypt(encrypted_data[4:], None)
        return message[0]

    async def _decrypt_credssp_message(self, encrypted_data, host):
        message, signature = await self.session.authmanager.authobj.decrypt(encrypted_data[4:], None)
        return message

    async def _decrypt_kerberos_message(self, encrypted_data, host):
        signature_length = struct.unpack("<i", encrypted_data[:4])[0]
        raw_header = encrypted_data[4:signature_length + 4]
        encrypted_rest = encrypted_data[signature_length + 4:]
        
        # Check for CFX token ID (0x0504) which indicates AES encryption
        is_cfx = len(raw_header) >= 2 and raw_header[0:2] == b'\x05\x04'
        
        if is_cfx:
            # For AES/CFX tokens, combine header + data for GSS_Unwrap_Combined
            # This handles the format returned by WinRM servers
            auth_ctx = self.session.authmanager.authobj.selected_authentication_context
            gssapi = getattr(auth_ctx, 'gssapi', None)
            
            if gssapi is not None and hasattr(gssapi, 'GSS_Unwrap_Combined'):
                combined = raw_header + encrypted_rest
                message, _ = gssapi.GSS_Unwrap_Combined(combined, 0, direction='accept')
                return message
        
        # Fallback to standard decryption (for RC4)
        # For Kerberos RC4, header is 24 bytes, confounder is first 8 bytes of encrypted data
        if signature_length == 24 and len(encrypted_rest) >= 8:
            encrypted_confounder = encrypted_rest[:8]
            encrypted_message = encrypted_rest[8:]
            # Reconstruct 32-byte token (header + confounder) for asyauth
            raw_signature = raw_header + encrypted_confounder
        else:
            raw_signature = raw_header
            encrypted_message = encrypted_rest

        # Re-wrap the raw token with GSSAPI OID for the decrypt function
        # GSSAPI OID: 1.2.840.113554.1.2.2 (Kerberos 5)
        gssapi_oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        inner_len = len(gssapi_oid) + len(raw_signature)
        if inner_len < 0x80:
            gssapi_header = b'\x60' + bytes([inner_len]) + gssapi_oid
        else:
            gssapi_header = b'\x60\x81' + bytes([inner_len]) + gssapi_oid
        signature = b'\x00'*8 + gssapi_header + raw_signature

        # Pass 0 as dummy sequence number - actual seq is derived from signature's SND_SEQ
        message, _ = await self.session.authmanager.authobj.decrypt(encrypted_message, 0, auth_data=signature)
        return message

    async def _build_ntlm_message(self, message, host):
        sealed_message, signature = await self.session.authmanager.authobj.encrypt(message, self.sequence_number)
        signature_length = struct.pack("<i", len(signature))
        self.sequence_number += 1
        return signature_length + signature + sealed_message

    async def _build_credssp_message(self, message, host):
        sealed_message, _ = await self.session.authmanager.authobj.encrypt(message, self.sequence_number) ##TODO: Check if this is correct
        cipher_negotiated = self.session.authmanager.authobj.get_cipher_name()
        trailer_length = self._get_credssp_trailer_length(len(message), cipher_negotiated)
        return struct.pack("<i", trailer_length) + sealed_message

    async def _build_kerberos_message(self, message, host):
        # Get the GSSAPI context to check if IOV is available
        auth_ctx = self.session.authmanager.authobj.selected_authentication_context
        gssapi = getattr(auth_ctx, 'gssapi', None)
        
        # Use IOV encryption if available (for AES encryption types)
        if gssapi is not None and hasattr(gssapi, 'GSS_Wrap_IOV'):
            enc_data, header, _ = gssapi.GSS_Wrap_IOV(message, self.sequence_number)
            self.sequence_number += 1
            signature_length = struct.pack("<i", len(header))
            return signature_length + header + enc_data
        
        # Fallback to standard encryption (for RC4)
        sealed_message, signature = await self.session.authmanager.authobj.encrypt(message, self.sequence_number)
        self.sequence_number += 1
        
        # Strip GSSAPI OID wrapper - WinRM expects raw header
        # GSSAPI token format: 0x60 <length> <OID> <inner content>
        if signature[0] == 0x60:
            # Parse ASN.1 length to find OID
            if signature[1] < 0x80:
                offset = 2
            elif signature[1] == 0x81:
                offset = 3
            else:
                offset = 4
            # Skip OID tag (0x06) and length
            if signature[offset] == 0x06:
                oid_len = signature[offset + 1]
                inner_offset = offset + 2 + oid_len
                signature = signature[inner_offset:]
        
        # For Kerberos RC4, the token from asyauth is 32 bytes:
        # - 24 bytes: header (TOK_ID, SGN_ALG, SEAL_ALG, Filler, SND_SEQ, SGN_CKSUM)
        # - 8 bytes: encrypted confounder
        # WinRM expects: 24-byte signature, then confounder+encrypted_message
        if len(signature) == 32:
            header = signature[:24]
            encrypted_confounder = signature[24:32]
            signature_length = struct.pack("<i", len(header))
            return signature_length + header + encrypted_confounder + sealed_message
        
        signature_length = struct.pack("<i", len(signature))
        return signature_length + signature + sealed_message

    def _get_credssp_trailer_length(self, message_length, cipher_suite):
        # I really don't like the way this works but can't find a better way, MS
        # allows you to get this info through the struct SecPkgContext_StreamSizes
        # but there is no GSSAPI/OpenSSL equivalent so we need to calculate it
        # ourselves

        if re.match(r'^.*-GCM-[\w\d]*$', cipher_suite):
            # We are using GCM for the cipher suite, GCM has a fixed length of 16
            # bytes for the TLS trailer making it easy for us
            trailer_length = 16
        else:
            # We are not using GCM so need to calculate the trailer size. The
            # trailer length is equal to the length of the hmac + the length of the
            # padding required by the block cipher
            hash_algorithm = cipher_suite.split('-')[-1]

            # while there are other algorithms, SChannel doesn't support them
            # as of yet https://msdn.microsoft.com/en-us/library/windows/desktop/aa374757(v=vs.85).aspx
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
                # RC4 is a stream cipher so no padding would be added
                padding_length = 0
            elif "DES" in cipher_suite or "3DES" in cipher_suite:
                # 3DES is a 64 bit block cipher
                padding_length = 8 - (pre_pad_length % 8)
            else:
                # AES is a 128 bit block cipher
                padding_length = 16 - (pre_pad_length % 16)

            trailer_length = (pre_pad_length + padding_length) - message_length

        return trailer_length