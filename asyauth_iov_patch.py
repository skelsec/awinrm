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
        header: The 60-byte header
        direction: 'init' for initiator, 'accept' for acceptor
        
    Returns:
        tuple: (plaintext, None)
    """
    cipher = self.cipher_type()
    
    checksum_size = 12
    confounder_size = 16
    header_copy_size = 16
    data_len = len(enc_data)
    
    # Parse header (60 bytes)
    token = header[:16]
    trailer = header[16:]  # 44 bytes
    
    # Trailer structure (from rotation): enc_header_copy(16) + checksum(12) + enc_confounder(16)
    enc_header_copy = trailer[:header_copy_size]
    checksum = trailer[header_copy_size:header_copy_size + checksum_size]
    enc_confounder = trailer[header_copy_size + checksum_size:]
    
    # Reconstruct original cipher output: enc_confounder + enc_data + enc_header_copy + checksum
    cipher_output = enc_confounder + enc_data + enc_header_copy + checksum
    
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
    
    # decrypted = data + header_copy (confounder stripped by minikerberos)
    decrypted_data = decrypted[:data_len]
    return decrypted_data, None


def patch_gssapi_aes():
    """
    Apply IOV methods to GSSAPI_AES class.
    
    Call this before using IOV encryption.
    """
    if not hasattr(GSSAPI_AES, 'GSS_Wrap_IOV'):
        GSSAPI_AES.GSS_Wrap_IOV = GSS_Wrap_IOV
        GSSAPI_AES.GSS_Unwrap_IOV = GSS_Unwrap_IOV
        return True
    return False


# Auto-patch when imported
patch_gssapi_aes()

