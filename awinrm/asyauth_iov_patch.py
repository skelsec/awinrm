"""
Patch to add GSS_Wrap_IOV and GSS_Unwrap_IOV to asyauth's GSSAPI_AES class.

IOV (Input/Output Vector) style encryption produces:
- Header (60 bytes): token(16) + trailer(44)
- Data: encrypted plaintext (same size as input)

The trailer structure follows RFC 4121 rotation with RRC=28:
- trailer = enc_header_copy(16) + checksum(12) + enc_confounder(16)

This format is required by protocols like WinRM that use DCE-style GSSAPI.
"""

from asyauth.protocols.kerberos.gssapismb import (
    GSSAPI_AES, GSSWrapToken, FlagsField, KG_USAGE
)


def GSS_Wrap_IOV(self, data, seq_num):
    """
    Wrap data using IOV (Input/Output Vector) style output.
    
    Unlike GSS_Wrap which combines all output into rotated ciphertext,
    this method separates output into:
    - header: token(16) + trailer(44) = 60 bytes
    - data: encrypted plaintext (same size as input)
    
    The trailer follows RRC=28 rotation structure:
    - enc_header_copy(16) + checksum(12) + enc_confounder(16)
    
    Args:
        data: Plaintext data to encrypt
        seq_num: Sequence number for the token
        
    Returns:
        tuple: (encrypted_data, header, ec)
               encrypted_data: bytes - same length as input data
               header: bytes - 60 bytes for AES
               ec: int - extra count (always 0 for IOV)
    """
    cipher = self.cipher_type()
    data_len = len(data)
    
    # Build token with RRC=28 for IOV output
    t = GSSWrapToken()
    t.Flags = FlagsField.Sealed | FlagsField.AcceptorSubkey
    t.EC = 0  # No padding for IOV
    t.RRC = 28  # Per RFC 4121 section 4.2.5
    t.SND_SEQ = seq_num
    
    # For encryption, the header copy uses RRC=0
    t_for_encrypt = GSSWrapToken()
    t_for_encrypt.Flags = t.Flags
    t_for_encrypt.EC = 0
    t_for_encrypt.RRC = 0  # RRC=0 during encryption per RFC
    t_for_encrypt.SND_SEQ = seq_num
    header_copy = t_for_encrypt.to_bytes()  # 16 bytes
    
    # Plaintext = data + header_copy
    plaintext_for_cipher = data + header_copy
    
    # Encrypt: minikerberos adds confounder(16) and checksum(12)
    # Output: enc(confounder + data + header_copy) + checksum
    cipher_output = cipher.encrypt(
        self.session_key, 
        KG_USAGE.INITIATOR_SEAL.value, 
        plaintext_for_cipher, 
        None  # Random confounder
    )
    
    # Parse cipher output
    checksum_size = 12  # AES-HMAC-SHA1-96
    confounder_size = 16
    
    encrypted_payload = cipher_output[:-checksum_size]
    checksum = cipher_output[-checksum_size:]
    
    # Split encrypted payload: enc_confounder | enc_data | enc_header_copy
    enc_confounder = encrypted_payload[:confounder_size]
    enc_data = encrypted_payload[confounder_size:confounder_size + data_len]
    enc_header_copy = encrypted_payload[confounder_size + data_len:]
    
    # Build trailer with rotation structure (RRC=28):
    # Rotation of: enc_confounder(16) + enc_data(N) + enc_header_copy(16) + checksum(12)
    # Results in: enc_header_copy(16) + checksum(12) + enc_confounder(16) + enc_data(N)
    # Trailer = first 44 bytes = enc_header_copy(16) + checksum(12) + enc_confounder(16)
    trailer = enc_header_copy + checksum + enc_confounder
    
    # IOV header = token(16) + trailer(44) = 60 bytes
    header = t.to_bytes() + trailer
    
    return enc_data, header, 0


def GSS_Unwrap_IOV(self, enc_data, seq_num, header, direction='init'):
    """
    Unwrap IOV-style wrapped data.
    
    Args:
        enc_data: The encrypted data portion
        seq_num: Sequence number (for verification)
        header: The header (60+ bytes, varies with EC)
        direction: 'init' for initiator, 'accept' for acceptor
        
    Returns:
        tuple: (plaintext, None)
    """
    cipher = self.cipher_type()
    
    checksum_size = 12
    confounder_size = 16
    header_copy_size = 16
    
    # Parse token header (first 16 bytes)
    token = header[:16]
    
    # Extract EC and RRC from token
    ec = int.from_bytes(token[4:6], 'big')
    rrc = int.from_bytes(token[6:8], 'big')
    
    # Trailer is everything after token
    trailer = header[16:]
    
    # The trailer structure depends on RRC rotation
    # For RRC=28 with EC padding:
    # Original order: enc_confounder(16) + enc_data(N) + enc_padding(EC) + enc_header_copy(16) + checksum(12)
    # After rotate right by RRC+EC: last (RRC+EC) bytes go first
    # So rotated = enc_header_copy(16) + checksum(12) + enc_confounder(16) + enc_data(N) + enc_padding(EC)
    # 
    # The trailer contains all except enc_data portion:
    # trailer = enc_header_copy(16) + checksum(12) + enc_confounder(16) + enc_padding(EC)
    
    trailer_expected_size = header_copy_size + checksum_size + confounder_size + ec
    
    # Extract components from trailer
    enc_header_copy = trailer[:header_copy_size]
    checksum = trailer[header_copy_size:header_copy_size + checksum_size]
    enc_confounder = trailer[header_copy_size + checksum_size:header_copy_size + checksum_size + confounder_size]
    enc_padding = trailer[header_copy_size + checksum_size + confounder_size:]
    
    # Reconstruct original cipher output (unrotated order):
    # enc_confounder + enc_data + enc_padding + enc_header_copy + checksum
    cipher_output = enc_confounder + enc_data + enc_padding + enc_header_copy + checksum
    
    # Decrypt - use appropriate key usage for direction
    if direction == 'init':
        key_usage = KG_USAGE.INITIATOR_SEAL.value
    else:
        key_usage = KG_USAGE.ACCEPTOR_SEAL.value
    
    decrypted = cipher.decrypt(
        self.session_key, 
        key_usage,
        cipher_output
    )
    
    # decrypted = data + padding(EC) + header_copy (confounder stripped by minikerberos)
    # We need to strip both padding and header_copy
    data_len = len(enc_data)
    decrypted_data = decrypted[:data_len]
    return decrypted_data, None


def GSS_Unwrap_Combined(self, combined_data, seq_num, direction='init'):
    """
    Unwrap a combined header+data blob.
    
    This handles the format returned by WinRM servers where the response is:
    header(60) + encrypted_data(N) combined into a single blob.
    
    Args:
        combined_data: The combined header + encrypted data
        seq_num: Sequence number (for verification)
        direction: 'init' for initiator, 'accept' for acceptor
        
    Returns:
        tuple: (plaintext, None)
    """
    cipher = self.cipher_type()
    
    # Parse token header (first 16 bytes)
    token = combined_data[:16]
    
    # Extract EC and RRC from token
    ec = int.from_bytes(token[4:6], 'big')
    rrc = int.from_bytes(token[6:8], 'big')
    
    # The rest is the rotated ciphertext
    rotated_ciphertext = combined_data[16:]
    
    # Unrotate to get original ciphertext
    cipher_text = self.unrotate(rotated_ciphertext, rrc + ec)
    
    # Decrypt - use appropriate key usage for direction
    if direction == 'init':
        key_usage = KG_USAGE.INITIATOR_SEAL.value
    else:
        key_usage = KG_USAGE.ACCEPTOR_SEAL.value
    
    plain_text = cipher.decrypt(self.session_key, key_usage, cipher_text)
    
    # Remove EC padding and 16-byte header copy from end
    return plain_text[:-(ec + 16)], None


def patch_gssapi_aes():
    """
    Apply IOV methods to GSSAPI_AES class.
    
    Call this before using IOV encryption.
    """
    if not hasattr(GSSAPI_AES, 'GSS_Wrap_IOV'):
        GSSAPI_AES.GSS_Wrap_IOV = GSS_Wrap_IOV
        GSSAPI_AES.GSS_Unwrap_IOV = GSS_Unwrap_IOV
        GSSAPI_AES.GSS_Unwrap_Combined = GSS_Unwrap_Combined
        return True
    return False


# ============================================================================
# RC4 Fixes
# ============================================================================

from asyauth.protocols.kerberos.gssapismb import GSSAPI_RC4, GSSWRAP_RC4
from unicrypto.symmetric import RC4
from unicrypto import hmac


def GSS_Wrap_RC4_Fixed(self, data, seq_num, direction='init', encrypt=True, auth_data=None):
    """
    Fixed GSS_Wrap for RC4 that correctly handles decryption.
    
    The original has a bug where it uses token.Confounder instead of wrap.Confounder
    when decrypting.
    """
    import os
    from unicrypto.hashlib import md5
    
    GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
    
    pad = (8 - (len(data) % 8)) & 0x7
    padStr = bytes([pad]) * pad
    data += padStr
    
    token = GSSWRAP_RC4()
    token.SEAL_ALG = b'\x10\x00'
    
    if direction == 'init':
        token.SND_SEQ = seq_num.to_bytes(4, 'big', signed=False) + b'\x00'*4
    else:
        token.SND_SEQ = seq_num.to_bytes(4, 'big', signed=False) + b'\xff'*4
        
    token.Confounder = os.urandom(8)
    
    temp = hmac.new(self.session_key.contents, digestmod='md5')
    temp.update(b'signaturekey\0')
    Ksign = temp.digest()
    
    id = 13
    Sgn_Cksum = md5(id.to_bytes(4, 'little', signed=False) + token.to_bytes()[:8] + token.Confounder + data).digest()
    temp = hmac.new(Ksign, digestmod='md5')
    temp.update(Sgn_Cksum)
    token.SGN_CKSUM = temp.digest()[:8]
    
    klocal = b''
    for b in self.session_key.contents:
        klocal += bytes([b ^ 0xf0])
        
    id = 0
    temp = hmac.new(klocal, digestmod='md5')
    temp.update(id.to_bytes(4, 'little', signed=False))
    temp = hmac.new(temp.digest(), digestmod='md5')
    temp.update(seq_num.to_bytes(4, 'big', signed=False))
    Kcrypt = temp.digest()
    
    id = 0
    temp = hmac.new(self.session_key.contents, digestmod='md5')
    temp.update(id.to_bytes(4, 'little', signed=False))
    temp = hmac.new(temp.digest(), digestmod='md5')
    temp.update(token.SGN_CKSUM)
    Kseq = temp.digest()
    
    token.SND_SEQ = RC4(Kseq).encrypt(token.SND_SEQ)
    
    if auth_data is not None:
        # Decryption path
        # BUG FIX: Original used auth_data[8 + len(GSS_WRAP_HEADER):] which is wrong
        # The token starts right after the GSSAPI OID header
        wrap = GSSWRAP_RC4.from_bytes(auth_data[len(GSS_WRAP_HEADER):])
        
        id = 0
        temp = hmac.new(self.session_key.contents, digestmod='md5')
        temp.update(id.to_bytes(4, 'little', signed=False))
        temp = hmac.new(temp.digest(), digestmod='md5')
        temp.update(wrap.SGN_CKSUM)
        
        snd_seq = RC4(temp.digest()).encrypt(wrap.SND_SEQ)
        
        id = 0
        temp = hmac.new(klocal, digestmod='md5')
        temp.update(id.to_bytes(4, 'little', signed=False))
        temp = hmac.new(temp.digest(), digestmod='md5')
        temp.update(snd_seq[:4])
        Kcrypt = temp.digest()
        
        rc4 = RC4(Kcrypt)
        # BUG FIX: Use wrap.Confounder from auth_data, not token.Confounder
        cipherText = rc4.decrypt(wrap.Confounder + data)[8:]
        
    elif encrypt is True:
        rc4 = RC4(Kcrypt)
        token.Confounder = rc4.encrypt(token.Confounder)
        cipherText = rc4.encrypt(data)
    
    else:
        cipherText = data
        
    finalData = GSS_WRAP_HEADER + token.to_bytes()
    return cipherText, finalData


def GSS_Unwrap_RC4_Fixed(self, data, seq_num, direction='init', auth_data=None):
    """Fixed GSS_Unwrap for RC4"""
    return GSS_Wrap_RC4_Fixed(self, data, seq_num, direction, False, auth_data)


def patch_gssapi_rc4():
    """Apply fixes to GSSAPI_RC4 class"""
    if not hasattr(GSSAPI_RC4, '_original_GSS_Wrap'):
        GSSAPI_RC4._original_GSS_Wrap = GSSAPI_RC4.GSS_Wrap
        GSSAPI_RC4._original_GSS_Unwrap = GSSAPI_RC4.GSS_Unwrap
        GSSAPI_RC4.GSS_Wrap = GSS_Wrap_RC4_Fixed
        GSSAPI_RC4.GSS_Unwrap = GSS_Unwrap_RC4_Fixed
        return True
    return False


# Auto-patch when imported
patch_gssapi_aes()
patch_gssapi_rc4()

