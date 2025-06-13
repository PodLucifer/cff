import os
import abc
import pickle
from typing import Tuple, Optional, Dict, Any
from collections import defaultdict

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hmac, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from nacl.public import PrivateKey, PublicKey, Box
from nacl.bindings import crypto_scalarmult
from nacl.encoding import RawEncoder

# --- Ed25519 for digital signatures ---
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

import hashlib

# --- PXAddress: Unique Address Abstraction for Multi-Device ---
class PXAddress:
    """
    PXAddress uniquely identifies a remote party (user/device) in Signal-style E2E communication.
    - name: user ID (phone number, username, etc.)
    - device_id: integer (to support multiple devices per user)
    """

    def __init__(self, name: str, device_id: int):
        self._name = name
        self._device_id = device_id

    def getName(self) -> str:
        """Returns the user name/identifier."""
        return self._name

    def getDeviceId(self) -> int:
        """Returns the device ID."""
        return self._device_id

    def toString(self) -> str:
        """Returns a string like 'alice.1'."""
        return f"{self._name}.{self._device_id}"

    def __eq__(self, other):
        return isinstance(other, PXAddress) and \
               self._name == other._name and \
               self._device_id == other._device_id

    def __hash__(self):
        return hash((self._name, self._device_id))

    def __repr__(self):
        return f"<PXAddress {self.toString()}>"

# --- NumericFingerprint: Calculation of Fingerprints for Identity Verification ---
class NumericFingerprint:
    """
    Implements Signal-style numeric fingerprint for identity key verification.
    Produces a numeric code (decimals) for two public keys and extra info.
    """

    @staticmethod
    def calculate(local_identity: bytes, remote_identity: bytes, info: bytes = b"PXFingerprint", digits: int = 60) -> str:
        """
        Returns a human-verifiable fingerprint string for two public keys.
        - local_identity: bytes (32)
        - remote_identity: bytes (32)
        - info: context string (default "PXFingerprint")
        """
        # Standard: SHA256 over sorted keys + info
        keys = sorted([local_identity, remote_identity])
        h = hashlib.sha256()
        h.update(keys[0])
        h.update(keys[1])
        h.update(info)
        digest = h.digest()
        # Convert to a decimal fingerprint (like Signal's 60-digit code)
        num = int.from_bytes(digest, "big")
        fingerprint = str(num).zfill(digits)[-digits:]  # pad/truncate to fixed size
        return fingerprint

# -- Constants --
MAX_SKIP = 1000
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
IV_SIZE = 16
HEADER_KEY_SIZE = 32
CHAIN_KEY_SIZE = 32
ROOT_KEY_SIZE = 32
MESSAGE_KEY_SIZE = 32

MSGKDF_INPUT = b'\x01'
CHAINKDF_INPUT = b'\x02'

# Application-specific info for HKDF
KDF_RK_INFO = b"DR:root"
KDF_RK_HE_INFO = b"DR:root:he"
KDF_AEAD_INFO = b"DR:aead"

# X3DH constants
X3DH_IDENTITY_KEY_INFO = b"X3DH:id"
X3DH_EPH_INFO = b"X3DH:eph"
X3DH_SHARED_SECRET_INFO = b"X3DH:ssk"
X3DH_DH_OUTPUT_SIZE = 32

# -- Errors --
class DoubleRatchetError(Exception): pass
class X3DHError(Exception): pass

# -- Utility functions --
def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, outlen: int) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=outlen,
        salt=salt,
        info=info,
    ).derive(ikm)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, SHA256())
    h.update(data)
    return h.finalize()

def aes256_cbc_hmac_encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """
    AEAD composed of:
    - AES-256-CBC with PKCS#7 padding
    - HMAC-SHA256 over (associated_data || ciphertext)
    Output: IV || ciphertext || HMAC
    """
    out = hkdf_sha256(
        salt=b"\x00" * 32,
        ikm=key,
        info=KDF_AEAD_INFO,
        outlen=AES_KEY_SIZE + HMAC_KEY_SIZE + IV_SIZE
    )
    enc_key, auth_key, iv = out[:AES_KEY_SIZE], out[AES_KEY_SIZE:AES_KEY_SIZE+HMAC_KEY_SIZE], out[AES_KEY_SIZE+HMAC_KEY_SIZE:]
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    mac = hmac_sha256(auth_key, associated_data + ct)[:16]  # Truncate HMAC to 128 bits
    return iv + ct + mac

def aes256_cbc_hmac_decrypt(key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    out = hkdf_sha256(
        salt=b"\x00" * 32,
        ikm=key,
        info=KDF_AEAD_INFO,
        outlen=AES_KEY_SIZE + HMAC_KEY_SIZE + IV_SIZE
    )
    enc_key, auth_key, iv = out[:AES_KEY_SIZE], out[AES_KEY_SIZE:AES_KEY_SIZE+HMAC_KEY_SIZE], out[AES_KEY_SIZE+HMAC_KEY_SIZE:]
    if len(ciphertext) < IV_SIZE + 16:
        raise DoubleRatchetError("Ciphertext too short")
    ct = ciphertext[IV_SIZE:-16]
    tag = ciphertext[-16:]
    if hmac_sha256(auth_key, associated_data + ct)[:16] != tag:
        raise DoubleRatchetError("Authentication failed")
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# -- Diffie-Hellman primitives (X25519) --
def generate_dh_keypair() -> Tuple[PrivateKey, PublicKey]:
    priv = PrivateKey.generate()
    return priv, priv.public_key

def dh(priv: PrivateKey, pub: PublicKey) -> bytes:
    # Returns raw X25519 scalar multiplication output (32 bytes)
    return crypto_scalarmult(priv.encode(RawEncoder), pub.encode(RawEncoder))

# -- Ed25519 Digital Signatures (added section) --
class Ed25519:
    """
    Utility class for Ed25519 digital signatures.
    """

    @staticmethod
    def generate_keypair() -> Tuple[SigningKey, VerifyKey]:
        """
        Generate a new Ed25519 keypair.
        Returns (signing_key, verify_key)
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        return signing_key, verify_key

    @staticmethod
    def sign(signing_key: SigningKey, message: bytes) -> bytes:
        """
        Sign the message using Ed25519.
        Returns the signature (signature + message).
        """
        # nacl.signing signs and attaches the message, but we only want the signature
        signed = signing_key.sign(message)
        return signed.signature  # Just the signature (64 bytes)

    @staticmethod
    def verify(verify_key: VerifyKey, message: bytes, signature: bytes) -> bool:
        """
        Verify the message and signature using Ed25519.
        Returns True if valid, False otherwise.
        """
        try:
            # NaCl expects signature+message, but we split them
            verify_key.verify(message, signature)
            return True
        except BadSignatureError:
            return False

    @staticmethod
    def export_signing_key(signing_key: SigningKey) -> bytes:
        """
        Export the signing key as bytes.
        """
        return signing_key.encode()

    @staticmethod
    def import_signing_key(data: bytes) -> SigningKey:
        """
        Import a signing key from bytes.
        """
        return SigningKey(data)

    @staticmethod
    def export_verify_key(verify_key: VerifyKey) -> bytes:
        """
        Export the verify key as bytes.
        """
        return verify_key.encode()

    @staticmethod
    def import_verify_key(data: bytes) -> VerifyKey:
        """
        Import a verify key from bytes.
        """
        return VerifyKey(data)

# -- KDF Chains --
def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    # Derive (root_key, chain_key) from root_key and DH output
    okm = hkdf_sha256(rk, dh_out, KDF_RK_INFO, ROOT_KEY_SIZE + CHAIN_KEY_SIZE)
    return okm[:ROOT_KEY_SIZE], okm[ROOT_KEY_SIZE:]

def kdf_rk_he(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes, bytes]:
    # For header encryption variant: (root_key, chain_key, next_header_key)
    okm = hkdf_sha256(rk, dh_out, KDF_RK_HE_INFO, ROOT_KEY_SIZE + CHAIN_KEY_SIZE + HEADER_KEY_SIZE)
    return okm[:ROOT_KEY_SIZE], okm[ROOT_KEY_SIZE:ROOT_KEY_SIZE+CHAIN_KEY_SIZE], okm[ROOT_KEY_SIZE+CHAIN_KEY_SIZE:]

def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    # Returns (next chain key, message key)
    if ck is None:
        raise DoubleRatchetError("Chain key is None")
    mk = hmac_sha256(ck, MSGKDF_INPUT)
    next_ck = hmac_sha256(ck, CHAINKDF_INPUT)
    return next_ck, mk

# -- Header encoding/decoding --
class Header:
    def __init__(self, dh_pub: bytes, pn: int, n: int):
        self.dh = dh_pub  # bytes (public key)
        self.pn = pn      # int
        self.n = n        # int

    def serialize(self) -> bytes:
        # Simple serialization: pubkey(32) || pn(4) || n(4)
        return self.dh + self.pn.to_bytes(4, 'big') + self.n.to_bytes(4, 'big')

    @staticmethod
    def deserialize(data: bytes) -> "Header":
        if len(data) < 32 + 4 + 4:
            raise DoubleRatchetError("Header too short")
        dh = data[:32]
        pn = int.from_bytes(data[32:36], 'big')
        n = int.from_bytes(data[36:40], 'big')
        return Header(dh, pn, n)

    def __repr__(self):
        return f"<Header dh={self.dh.hex()} pn={self.pn} n={self.n}>"

def concat_ad(ad: bytes, header: Header) -> bytes:
    # Prepend AD length (4 bytes) so parseable
    adlen = len(ad).to_bytes(4, 'big')
    return adlen + ad + header.serialize()

# -- AEAD wrappers --
def encrypt(mk: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    return aes256_cbc_hmac_encrypt(mk, plaintext, associated_data)

def decrypt(mk: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    return aes256_cbc_hmac_decrypt(mk, ciphertext, associated_data)

# -- Header encryption (AEAD) --
def h_encrypt(hk: bytes, header: Header) -> bytes:
    # Use header key to encrypt serialized header, associated_data is empty
    return aes256_cbc_hmac_encrypt(hk, header.serialize(), b'')

def h_decrypt(hk: Optional[bytes], enc_header: bytes) -> Optional[Header]:
    if hk is None:
        return None
    try:
        plaintext = aes256_cbc_hmac_decrypt(hk, enc_header, b'')
        return Header.deserialize(plaintext)
    except Exception:
        return None

# -- Double Ratchet State --
class DoubleRatchetState:
    """
    Core state for a Double Ratchet participant.
    """
    def __init__(self):
        # DH ratchet keys (private and public)
        self.DHs: Optional[PrivateKey] = None
        self.DHs_pub: Optional[PublicKey] = None
        self.DHr: Optional[bytes] = None  # remote public key (bytes)
        # Root, chain keys
        self.RK: Optional[bytes] = None
        self.CKs: Optional[bytes] = None
        self.CKr: Optional[bytes] = None
        # Message numbers
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        # Skipped message keys
        self.MKSKIPPED: Dict[Tuple[bytes, int], bytes] = {}
        # Header encryption keys (optional)
        self.HKs: Optional[bytes] = None
        self.HKr: Optional[bytes] = None
        self.NHKs: Optional[bytes] = None
        self.NHKr: Optional[bytes] = None

    def serialize(self) -> bytes:
        # Pickle is used for simple state serialization
        return pickle.dumps(self, protocol=pickle.HIGHEST_PROTOCOL)

    @staticmethod
    def deserialize(data: bytes) -> "DoubleRatchetState":
        return pickle.loads(data)

    def get_skipped_keys(self):
        """Returns the skipped message keys for storage (for missed messages)."""
        return self.MKSKIPPED.copy()

# --- SessionStore (SignalProtocolStore): Persistent Session Storage API ---
class SessionStore(abc.ABC):
    """
    Abstract session store for missed message keys and session state.
    Implementations should store SessionRecord (and skipped keys) persistently.
    """

    @abc.abstractmethod
    def putSession(self, address: PXAddress, sessionRecord: "SessionRecord"):
        """Store the session record (including skipped message keys) for PXAddress."""
        pass

    @abc.abstractmethod
    def getSession(self, address: PXAddress) -> Optional["SessionRecord"]:
        """Retrieve the session record for PXAddress."""
        pass

# --- SessionRecord: Holds all session state including skipped message keys ---
class SessionRecord:
    """
    Container for all session state, including skipped message keys.
    Used for serialization and persistent storage.
    """
    def __init__(self, state: DoubleRatchetState):
        self.state_bytes = state.serialize()
        self.skipped_keys = state.get_skipped_keys()  # Dict[(bytes, int), bytes]

    def get_state(self) -> DoubleRatchetState:
        return DoubleRatchetState.deserialize(self.state_bytes)

    def get_skipped_keys(self) -> Dict[Tuple[bytes, int], bytes]:
        return self.skipped_keys

# --- Message Whispering: Metadata for sending private messages to specific PXAddress(es) ---
class WhisperMessage:
    """
    Represents a 'whispered' message to a specific PXAddress.
    """
    def __init__(self, to: PXAddress, ciphertext: bytes, header: bytes, ad: bytes = b""):
        self.to = to
        self.ciphertext = ciphertext
        self.header = header
        self.ad = ad

    def __repr__(self):
        return f"<WhisperMessage to={self.to.toString()} len={len(self.ciphertext)}>"

# -- Double Ratchet (main API) --
class DoubleRatchet(metaclass=abc.ABCMeta):
    """
    Double Ratchet algorithm: stateful, production-grade implementation.
    - Can be initialized from a shared secret/root key and remote's DH public key.
    - Exposes encrypt() and decrypt() methods for message processing.
    - Optionally supports header encryption.
    - Does NOT maintain any network/transport; you must store and transmit headers/ciphertexts as needed.
    """

    def __init__(self, *, root_key: bytes, dh_pair: Optional[PrivateKey] = None,
                 dh_remote_pub: Optional[bytes] = None, header_keys: Optional[Dict[str, bytes]] = None,
                 skip_header_encryption: bool = True):  # <---- CHANGED: default skip_header_encryption to True
        """
        - root_key: Initial root key (32 bytes, from X3DH or equivalent).
        - dh_pair: Our initial DH private key (X25519, or None to generate).
        - dh_remote_pub: Remote's DH public key (bytes).
        - header_keys: Dict for header encryption: {'HKs':..., 'NHKs':..., 'HKr':..., 'NHKr':...}
        - skip_header_encryption: If True, header encryption is not used.
        """
        self.state = DoubleRatchetState()
        self.header_encryption = not skip_header_encryption
        # Initial setup: if header_encryption is used, require header_keys
        if self.header_encryption:
            # Header encryption variant
            if not header_keys or not all(k in header_keys for k in ('HKs', 'NHKs', 'HKr', 'NHKr')):
                raise ValueError("Header keys required for header encryption variant")
            self._init_header_encryption(root_key, dh_pair, dh_remote_pub, header_keys)
        else:
            self._init_plain(root_key, dh_pair, dh_remote_pub)

    def _init_plain(self, root_key, dh_pair, dh_remote_pub):
        # Standard Double Ratchet (no header encryption)
        if dh_pair is None:
            self.state.DHs, self.state.DHs_pub = generate_dh_keypair()
        else:
            self.state.DHs = dh_pair
            self.state.DHs_pub = dh_pair.public_key
        if dh_remote_pub is None:
            raise ValueError("Remote DH public key required for initialization")
        self.state.DHr = dh_remote_pub
        rk, cks = kdf_rk(root_key, dh(self.state.DHs, PublicKey(dh_remote_pub)))
        self.state.RK = rk
        self.state.CKs = cks
        self.state.CKr = None
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.PN = 0
        self.state.MKSKIPPED = {}

    def _init_header_encryption(self, root_key, dh_pair, dh_remote_pub, header_keys):
        # Header encryption variant (requires header_keys)
        if not header_keys or not all(k in header_keys for k in ('HKs', 'NHKs', 'HKr', 'NHKr')):
            raise ValueError("Header keys required for header encryption variant")
        if dh_pair is None:
            self.state.DHs, self.state.DHs_pub = generate_dh_keypair()
        else:
            self.state.DHs = dh_pair
            self.state.DHs_pub = dh_pair.public_key
        if dh_remote_pub is None:
            raise ValueError("Remote DH public key required for initialization")
        self.state.DHr = dh_remote_pub
        rk, cks, nhks = kdf_rk_he(root_key, dh(self.state.DHs, PublicKey(dh_remote_pub)))
        self.state.RK = rk
        self.state.CKs = cks
        self.state.CKr = None
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.PN = 0
        self.state.MKSKIPPED = {}
        self.state.HKs = header_keys['HKs']
        self.state.NHKs = nhks
        self.state.HKr = header_keys['HKr']
        self.state.NHKr = header_keys['NHKr']

    def encrypt(self, plaintext: bytes, ad: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypts a message.
        Returns: (header, ciphertext) if header encryption is off,
                 (enc_header, ciphertext) if header encryption is on.
        """
        if self.header_encryption:
            return self._encrypt_he(plaintext, ad)
        else:
            return self._encrypt_plain(plaintext, ad)

    def _encrypt_plain(self, plaintext: bytes, ad: bytes) -> Tuple[bytes, bytes]:
        self.state.CKs, mk = kdf_ck(self.state.CKs)
        header = Header(self.state.DHs_pub.encode(RawEncoder), self.state.PN, self.state.Ns)
        out_header = header.serialize()
        self.state.Ns += 1
        ct = encrypt(mk, plaintext, concat_ad(ad, header))
        return out_header, ct

    def _encrypt_he(self, plaintext: bytes, ad: bytes) -> Tuple[bytes, bytes]:
        self.state.CKs, mk = kdf_ck(self.state.CKs)
        header = Header(self.state.DHs_pub.encode(RawEncoder), self.state.PN, self.state.Ns)
        enc_header = h_encrypt(self.state.HKs, header)
        self.state.Ns += 1
        ct = encrypt(mk, plaintext, concat_ad(ad, enc_header))
        return enc_header, ct

    def whisper(self, to: PXAddress, plaintext: bytes, ad: bytes = b'') -> WhisperMessage:
        """
        Encrypts a message as a 'whisper' to a specific PXAddress (device).
        Returns a WhisperMessage which bundles ciphertext, header, and address.
        """
        header, ciphertext = self.encrypt(plaintext, ad)
        return WhisperMessage(to, ciphertext, header, ad)

    def decrypt(self, header: bytes, ciphertext: bytes, ad: bytes = b'') -> bytes:
        """
        Decrypts a message.
        header: raw or encrypted header, depending on mode.
        ciphertext: encrypted message.
        ad: associated data.
        Returns: plaintext
        """
        if self.header_encryption:
            return self._decrypt_he(header, ciphertext, ad)
        else:
            return self._decrypt_plain(header, ciphertext, ad)

    def _decrypt_plain(self, header_bytes: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        header = Header.deserialize(header_bytes)
        # Step 1: Try skipped message keys
        pt = self._try_skipped_message_keys((header.dh, header.n), ciphertext, concat_ad(ad, header))
        if pt is not None:
            return pt
        # Step 2: DH ratchet step if new key received
        if header.dh != (self.state.DHr if self.state.DHr else b''):
            self._skip_message_keys(header.pn)
            self._dh_ratchet(header)
        self._skip_message_keys(header.n)
        self.state.CKr, mk = kdf_ck(self.state.CKr)
        self.state.Nr += 1
        return decrypt(mk, ciphertext, concat_ad(ad, header))

    def _decrypt_he(self, enc_header: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        # Step 1: Try skipped message keys for header encryption
        pt = self._try_skipped_message_keys_he(enc_header, ciphertext, ad)
        if pt is not None:
            return pt
        header, dh_ratchet = self._decrypt_header(enc_header)
        if dh_ratchet:
            self._skip_message_keys_he(header.pn)
            self._dh_ratchet_he(header)
        self._skip_message_keys_he(header.n)
        self.state.CKr, mk = kdf_ck(self.state.CKr)
        self.state.Nr += 1
        return decrypt(mk, ciphertext, concat_ad(ad, enc_header))

    # -- Skipped message key logic --
    def _try_skipped_message_keys(self, key: Tuple[bytes, int], ciphertext: bytes, ad: bytes) -> Optional[bytes]:
        if key in self.state.MKSKIPPED:
            mk = self.state.MKSKIPPED[key]
            del self.state.MKSKIPPED[key]
            return decrypt(mk, ciphertext, ad)
        return None

    def _skip_message_keys(self, until: int):
        if self.state.Nr + MAX_SKIP < until:
            raise DoubleRatchetError("Too many skipped message keys")
        if self.state.CKr is not None:
            while self.state.Nr < until:
                self.state.CKr, mk = kdf_ck(self.state.CKr)
                self.state.MKSKIPPED[(self.state.DHr, self.state.Nr)] = mk
                self.state.Nr += 1

    # -- DH ratchet step (plain) --
    def _dh_ratchet(self, header: Header):
        self.state.PN = self.state.Ns
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.DHr = header.dh
        self.state.RK, self.state.CKr = kdf_rk(self.state.RK, dh(self.state.DHs, PublicKey(self.state.DHr)))
        self.state.DHs, self.state.DHs_pub = generate_dh_keypair()
        self.state.RK, self.state.CKs = kdf_rk(self.state.RK, dh(self.state.DHs, PublicKey(self.state.DHr)))

    # -- Header encryption skipped keys --
    def _try_skipped_message_keys_he(self, enc_header: bytes, ciphertext: bytes, ad: bytes) -> Optional[bytes]:
        for (hk, n), mk in list(self.state.MKSKIPPED.items()):
            header = h_decrypt(hk, enc_header)
            if header is not None and header.n == n:
                del self.state.MKSKIPPED[(hk, n)]
                return decrypt(mk, ciphertext, concat_ad(ad, enc_header))
        return None

    def _skip_message_keys_he(self, until: int):
        if self.state.Nr + MAX_SKIP < until:
            raise DoubleRatchetError("Too many skipped message keys")
        if self.state.CKr is not None:
            while self.state.Nr < until:
                self.state.CKr, mk = kdf_ck(self.state.CKr)
                self.state.MKSKIPPED[(self.state.HKr, self.state.Nr)] = mk
                self.state.Nr += 1

    def _decrypt_header(self, enc_header: bytes) -> Tuple[Header, bool]:
        header = h_decrypt(self.state.HKr, enc_header)
        if header is not None:
            return header, False
        header = h_decrypt(self.state.NHKr, enc_header)
        if header is not None:
            return header, True
        raise DoubleRatchetError("Header decryption failed")

    # -- DH ratchet step (header encryption) --
    def _dh_ratchet_he(self, header: Header):
        self.state.PN = self.state.Ns
        self.state.Ns = 0
        self.state.Nr = 0
        self.state.HKs = self.state.NHKs
        self.state.HKr = self.state.NHKr
        self.state.DHr = header.dh
        self.state.RK, self.state.CKr, self.state.NHKr = kdf_rk_he(self.state.RK, dh(self.state.DHs, PublicKey(self.state.DHr)))
        self.state.DHs, self.state.DHs_pub = generate_dh_keypair()
        self.state.RK, self.state.CKs, self.state.NHKs = kdf_rk_he(self.state.RK, dh(self.state.DHs, PublicKey(self.state.DHr)))

    # -- Export/import state for persistence --
    def export_state(self) -> bytes:
        return self.state.serialize()

    def import_state(self, data: bytes):
        self.state = DoubleRatchetState.deserialize(data)

    # -- For test/debug, not for production use --
    def dump_state(self) -> Dict[str, Any]:
        return {
            "DHs": self.state.DHs.encode(RawEncoder).hex() if self.state.DHs else None,
            "DHs_pub": self.state.DHs_pub.encode(RawEncoder).hex() if self.state.DHs_pub else None,
            "DHr": self.state.DHr.hex() if self.state.DHr else None,
            "RK": self.state.RK.hex() if self.state.RK else None,
            "CKs": self.state.CKs.hex() if self.state.CKs else None,
            "CKr": self.state.CKr.hex() if self.state.CKr else None,
            "Ns": self.state.Ns,
            "Nr": self.state.Nr,
            "PN": self.state.PN,
            "MKSKIPPED": { (k[0].hex(), k[1]) : v.hex() for k, v in self.state.MKSKIPPED.items() },
            "HKs": self.state.HKs.hex() if self.state.HKs else None,
            "HKr": self.state.HKr.hex() if self.state.HKr else None,
            "NHKs": self.state.NHKs.hex() if self.state.NHKs else None,
            "NHKr": self.state.NHKr.hex() if self.state.NHKr else None,
        }

# -- X3DH KEY AGREEMENT PROTOCOL --
class X3DH:
    """
    Implements the X3DH key agreement protocol for establishing a shared secret
    suitable as root key for Double Ratchet.
    No I/O, networking, or serialization included. All keys are X25519.
    Public keys are bytes (32), private keys are nacl.public.PrivateKey.
    """

    @staticmethod
    def generate_identity_keypair() -> Tuple[PrivateKey, PublicKey]:
        """Generate a long-term identity key pair."""
        priv = PrivateKey.generate()
        return priv, priv.public_key

    @staticmethod
    def generate_signed_prekey() -> Tuple[PrivateKey, PublicKey]:
        """Generate a signed prekey (SPK). (Signature not handled here)"""
        priv = PrivateKey.generate()
        return priv, priv.public_key

    @staticmethod
    def generate_onetime_prekey() -> Tuple[PrivateKey, PublicKey]:
        """Generate a one-time prekey (OPK)."""
        priv = PrivateKey.generate()
        return priv, priv.public_key

    @staticmethod
    def dh(priv: PrivateKey, pub: bytes) -> bytes:
        """Perform DH with a nacl PrivateKey and a raw public key (bytes)."""
        return crypto_scalarmult(priv.encode(RawEncoder), pub)

    @staticmethod
    def sender_calculate_shared_secret(
        ik_sender_priv: PrivateKey,
        ek_sender_priv: PrivateKey,
        ik_recipient_pub: bytes,
        spk_recipient_pub: bytes,
        opk_recipient_pub: Optional[bytes] = None,
        info: bytes = X3DH_SHARED_SECRET_INFO
    ) -> Tuple[bytes, bytes, bytes, Optional[bytes]]:
        """
        Sender combines four DHs (as in X3DH):
          DH1 = DH(IK_sender, SPK_recipient)
          DH2 = DH(EK_sender, IK_recipient)
          DH3 = DH(EK_sender, SPK_recipient)
          DH4 = DH(EK_sender, OPK_recipient)  (optional, if OPK is published)
        Returns (shared_secret, ek_sender_pub, used_opk_pub, opk_pub)
        """
        DH1 = X3DH.dh(ik_sender_priv, spk_recipient_pub)
        DH2 = X3DH.dh(ek_sender_priv, ik_recipient_pub)
        DH3 = X3DH.dh(ek_sender_priv, spk_recipient_pub)
        if opk_recipient_pub:
            DH4 = X3DH.dh(ek_sender_priv, opk_recipient_pub)
            dhs = DH1 + DH2 + DH3 + DH4
        else:
            dhs = DH1 + DH2 + DH3
        shared_secret = hkdf_sha256(
            salt=b'\x00' * 32,
            ikm=dhs,
            info=info,
            outlen=ROOT_KEY_SIZE
        )
        return shared_secret, ek_sender_priv.public_key.encode(RawEncoder), opk_recipient_pub, opk_recipient_pub

    @staticmethod
    def recipient_calculate_shared_secret(
        ik_recipient_priv: PrivateKey,
        spk_recipient_priv: PrivateKey,
        ek_sender_pub: bytes,
        ik_sender_pub: bytes,
        opk_recipient_priv: Optional[PrivateKey] = None,
        info: bytes = X3DH_SHARED_SECRET_INFO
    ) -> bytes:
        """
        Recipient computes the same shared secret as sender.
        """
        DH1 = X3DH.dh(ik_recipient_priv, spk_recipient_priv.public_key.encode(RawEncoder))  # Not needed, see X3DH spec.
        DH1 = X3DH.dh(ik_recipient_priv, spk_recipient_priv.public_key.encode(RawEncoder))  # Not used
        DH1 = X3DH.dh(ik_recipient_priv, spk_recipient_priv.public_key.encode(RawEncoder))  # Not used
        DH1 = X3DH.dh(ik_recipient_priv, spk_recipient_priv.public_key.encode(RawEncoder))  # Not used

        # Compute from sender's keys
        DH1 = X3DH.dh(ik_recipient_priv, ek_sender_pub)  # IK_r, EK_s
        DH2 = X3DH.dh(spk_recipient_priv, ik_sender_pub)  # SPK_r, IK_s
        DH3 = X3DH.dh(spk_recipient_priv, ek_sender_pub)  # SPK_r, EK_s
        if opk_recipient_priv:
            DH4 = X3DH.dh(opk_recipient_priv, ek_sender_pub)  # OPK_r, EK_s
            dhs = DH1 + DH2 + DH3 + DH4
        else:
            dhs = DH1 + DH2 + DH3
        shared_secret = hkdf_sha256(
            salt=b'\x00' * 32,
            ikm=dhs,
            info=info,
            outlen=ROOT_KEY_SIZE
        )
        return shared_secret
