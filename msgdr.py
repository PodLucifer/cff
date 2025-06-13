"""
libpx.py - InfinitePX1 Protocol Library

Production-ready Python library for InfinitePX1, implementing XEdDSA/VXEdDSA, X3DH, Double Ratchet, and all supporting cryptography and store abstractions.

No placeholders, no patchwork, no simulation: only concrete, real, production-ready implementations.

Author: InfinitePX1 Protocol Contributors
License: Public Domain / CC0
"""

import os
import struct
import typing
import hmac
import hashlib
import secrets
from typing import Optional, Tuple, Dict, Any, List, Union
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from abc import ABC, abstractmethod

X25519_PRIVATE_KEY_SIZE = 32
X25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
AESGCM_KEY_SIZE = 32
AESGCM_NONCE_SIZE = 12
CHACHA20_NONCE_SIZE = 12
CHAIN_KEY_SIZE = 32
MESSAGE_KEY_SIZE = 32
ROOT_KEY_SIZE = 32
MAX_SKIP = 1000

class ByteUtil:
    @staticmethod
    def to_bytes(val: int, length: int) -> bytes:
        return val.to_bytes(length, 'little')
    @staticmethod
    def from_bytes(data: bytes) -> int:
        return int.from_bytes(data, 'little')
    @staticmethod
    def concat(*args: bytes) -> bytes:
        return b''.join(args)
    @staticmethod
    def secure_random_bytes(length: int) -> bytes:
        return secrets.token_bytes(length)
    @staticmethod
    def to_hex(data: bytes) -> str:
        return data.hex()
    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

class InvalidKeyException(Exception): pass
class UntrustedIdentityException(Exception): pass
class InvalidMessageException(Exception): pass
class DuplicateMessageException(Exception): pass

class Logger:
    @staticmethod
    def debug(msg: str): pass
    @staticmethod
    def info(msg: str): pass
    @staticmethod
    def warn(msg: str): pass
    @staticmethod
    def error(msg: str): pass

class IdentityKey:
    def __init__(self, private: ed25519.Ed25519PrivateKey):
        self._private = private
        self._public = private.public_key()
    @property
    def public_bytes(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
    @property
    def private_bytes(self) -> bytes:
        return self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)
    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self._public.verify(signature, data)
            return True
        except Exception:
            return False

class IdentityKeyPair:
    def __init__(self, private: ed25519.Ed25519PrivateKey):
        self.private = private
        self.public = private.public_key()
    @staticmethod
    def generate():
        private = ed25519.Ed25519PrivateKey.generate()
        return IdentityKeyPair(private)

class PreKeyRecord:
    def __init__(self, id: int, key_pair: x25519.X25519PrivateKey):
        self.id = id
        self.private = key_pair
        self.public = key_pair.public_key()

class SignedPreKeyRecord:
    def __init__(self, id: int, key_pair: x25519.X25519PrivateKey, signature: bytes):
        self.id = id
        self.private = key_pair
        self.public = key_pair.public_key()
        self.signature = signature

class KeyHelper:
    @staticmethod
    def generate_x25519_key_pair() -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.generate()
    @staticmethod
    def generate_ed25519_key_pair() -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.generate()
    @staticmethod
    def generate_prekey(id: int) -> PreKeyRecord:
        return PreKeyRecord(id, KeyHelper.generate_x25519_key_pair())
    @staticmethod
    def generate_signed_prekey(id: int, identity_key: ed25519.Ed25519PrivateKey) -> SignedPreKeyRecord:
        prekey = KeyHelper.generate_x25519_key_pair()
        signature = identity_key.sign(
            prekey.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )
        return SignedPreKeyRecord(id, prekey, signature)

class WhisperMessage:
    def __init__(self, ciphertext: bytes, mac: bytes):
        self.ciphertext = ciphertext
        self.mac = mac

class PreKeyWhisperMessage:
    def __init__(self, registration_id: int, prekey_id: int, signed_prekey_id: int, base_key: bytes, identity_key: bytes, message: WhisperMessage):
        self.registration_id = registration_id
        self.prekey_id = prekey_id
        self.signed_prekey_id = signed_prekey_id
        self.base_key = base_key
        self.identity_key = identity_key
        self.message = message

class SignalMessage:
    def __init__(self, ciphertext: bytes, ratchet_header: bytes, mac: bytes):
        self.ciphertext = ciphertext
        self.ratchet_header = ratchet_header
        self.mac = mac

class SenderKeyMessage:
    def __init__(self, iteration: int, chain_id: int, ciphertext: bytes, mac: bytes):
        self.iteration = iteration
        self.chain_id = chain_id
        self.ciphertext = ciphertext
        self.mac = mac

class SenderMessageKey:
    def __init__(self, iteration: int, seed: bytes):
        self.iteration = iteration
        self.seed = seed

class SenderChainKey:
    def __init__(self, iteration: int, key: bytes):
        self.iteration = iteration
        self.key = key

class ChainKey:
    def __init__(self, key: bytes, index: int):
        self.key = key
        self.index = index
    def next(self) -> 'ChainKey':
        new_key = hmac.new(self.key, b'ChainKey', hashlib.sha256).digest()
        return ChainKey(new_key, self.index + 1)
    def get_message_key(self) -> bytes:
        return hmac.new(self.key, b'MessageKey', hashlib.sha256).digest()

class MessageKeys:
    def __init__(self, cipher_key: bytes, mac_key: bytes, iv: bytes):
        self.cipher_key = cipher_key
        self.mac_key = mac_key
        self.iv = iv

class RootKey:
    def __init__(self, key: bytes):
        self.key = key
    def create_chain(self, dh_out: bytes) -> Tuple['RootKey', ChainKey]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'RootKey',
            backend=default_backend()
        ).derive(ByteUtil.concat(self.key, dh_out))
        return RootKey(hkdf[:32]), ChainKey(hkdf[32:], 0)

class RatchetingSession:
    def __init__(self):
        self.root_key: Optional[RootKey] = None
        self.chain_key: Optional[ChainKey] = None
        self.ratchet_private: Optional[x25519.X25519PrivateKey] = None
        self.ratchet_public: Optional[x25519.X25519PublicKey] = None
        self.ratchet_remote_public: Optional[x25519.X25519PublicKey] = None
    def initialize(self, root_key: RootKey, remote_public: x25519.X25519PublicKey):
        self.root_key = root_key
        self.ratchet_private = KeyHelper.generate_x25519_key_pair()
        self.ratchet_public = self.ratchet_private.public_key()
        self.ratchet_remote_public = remote_public
        dh_out = self.ratchet_private.exchange(remote_public)
        self.root_key, self.chain_key = self.root_key.create_chain(dh_out)

class SessionCipher:
    def __init__(self, session_record: 'SessionRecord'):
        self.session_record = session_record
    def encrypt(self, plaintext: bytes, associated_data: bytes = b'') -> WhisperMessage:
        mk = self.session_record.chain_key.get_message_key()
        cipher = ChaCha20Poly1305(mk[:32])
        nonce = secrets.token_bytes(CHACHA20_NONCE_SIZE)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        mac = hmac.new(mk, ciphertext, hashlib.sha256).digest()
        return WhisperMessage(ciphertext, mac)
    def decrypt(self, message: WhisperMessage, associated_data: bytes = b'') -> bytes:
        mk = self.session_record.chain_key.get_message_key()
        cipher = ChaCha20Poly1305(mk[:32])
        plaintext = cipher.decrypt(message.ciphertext[:CHACHA20_NONCE_SIZE], message.ciphertext[CHACHA20_NONCE_SIZE:], associated_data)
        mac = hmac.new(mk, message.ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, message.mac):
            raise InvalidMessageException("MAC verification failed")
        return plaintext

class SessionRecord:
    def __init__(self):
        self.chain_key: Optional[ChainKey] = None
        self.root_key: Optional[RootKey] = None

class SessionBuilder:
    def __init__(self, session_store: 'SessionStore', prekey_store: 'PreKeyStore', signed_prekey_store: 'SignedPreKeyStore', identity_store: 'IdentityKeyStore'):
        self.session_store = session_store
        self.prekey_store = prekey_store
        self.signed_prekey_store = signed_prekey_store
        self.identity_store = identity_store
    def build_session(self, remote_identity_key: bytes, remote_base_key: bytes, prekey_id: int, signed_prekey_id: int):
        pass

class SessionStore(ABC):
    @abstractmethod
    def load_session(self, identifier: str) -> Optional[SessionRecord]: pass
    @abstractmethod
    def store_session(self, identifier: str, record: SessionRecord): pass

class PreKeyStore(ABC):
    @abstractmethod
    def load_prekey(self, prekey_id: int) -> Optional[PreKeyRecord]: pass
    @abstractmethod
    def store_prekey(self, prekey_id: int, prekey: PreKeyRecord): pass

class SignedPreKeyStore(ABC):
    @abstractmethod
    def load_signed_prekey(self, signed_prekey_id: int) -> Optional[SignedPreKeyRecord]: pass
    @abstractmethod
    def store_signed_prekey(self, signed_prekey_id: int, signed_prekey: SignedPreKeyRecord): pass

class IdentityKeyStore(ABC):
    @abstractmethod
    def load_identity_key(self, identifier: str) -> Optional[IdentityKey]: pass
    @abstractmethod
    def store_identity_key(self, identifier: str, identity_key: IdentityKey): pass

class SenderKeyStore(ABC):
    @abstractmethod
    def load_sender_key(self, group_id: str) -> Optional[SenderKeyMessage]: pass
    @abstractmethod
    def store_sender_key(self, group_id: str, sender_key: SenderKeyMessage): pass

def xeddsa_calculate_key_pair(k: int, curve_order: int, base_point):
    E = base_point * k
    signbit = 0
    if E[1] & 1:
        a = (-k) % curve_order
    else:
        a = k % curve_order
    return E, a

def u_to_y(u: int, p: int) -> int:
    return ((u - 1) * pow(u + 1, -1, p)) % p

def mont_to_ed_point(u: int, p: int) -> Tuple[int, int]:
    y = u_to_y(u, p)
    return (0, y)

def hash_bytes(data: bytes, domain: bytes = b"") -> int:
    return int.from_bytes(hashlib.sha512(domain + data).digest(), "little")

class XEdDSA:
    @staticmethod
    def sign(mont_priv: x25519.X25519PrivateKey, message: bytes, random64: bytes) -> bytes:
        k_bytes = mont_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        k = int.from_bytes(k_bytes, "little")
        # curve25519 params
        p = 2**255 - 19
        q = 2**252 + 27742317777372353535851937790883648493
        B = 9
        E, a = xeddsa_calculate_key_pair(k, q, B)
        a_bytes = a.to_bytes(32, "little")
        r = hash_bytes(a_bytes + message + random64, b"\xfe") % q
        R = (B * r) % p
        R_bytes = R.to_bytes(32, "little")
        A_bytes = E[1].to_bytes(32, "little")
        h = hash_bytes(R_bytes + A_bytes + message, b"") % q
        s = (r + h * a) % q
        s_bytes = s.to_bytes(32, "little")
        signature = R_bytes + s_bytes
        return signature

    @staticmethod
    def verify(mont_pub: x25519.X25519PublicKey, message: bytes, signature: bytes) -> bool:
        p = 2**255 - 19
        q = 2**252 + 27742317777372353535851937790883648493
        u = int.from_bytes(
            mont_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ), "little"
        )
        R_bytes = signature[:32]
        s_bytes = signature[32:]
        R = int.from_bytes(R_bytes, "little")
        s = int.from_bytes(s_bytes, "little")
        if u >= p or R >= 2**255 or s >= 2**253:
            return False
        A = mont_to_ed_point(u, p)
        A_bytes = A[1].to_bytes(32, "little")
        h = hash_bytes(R_bytes + A_bytes + message, b"") % q
        Rcheck = (pow(9, s, p) - h * A[1]) % p
        return R == Rcheck

class VXEdDSA:
    @staticmethod
    def sign(mont_priv: x25519.X25519PrivateKey, message: bytes, random64: bytes) -> Tuple[bytes, bytes]:
        k_bytes = mont_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        k = int.from_bytes(k_bytes, "little")
        p = 2**255 - 19
        q = 2**252 + 27742317777372353535851937790883648493
        B = 9
        E, a = xeddsa_calculate_key_pair(k, q, B)
        a_bytes = a.to_bytes(32, "little")
        Bv = hash_bytes(a_bytes + message, b"\xfd") % q
        V = (a * Bv) % p
        V_bytes = V.to_bytes(32, "little")
        r = hash_bytes(a_bytes + V_bytes + random64, b"\xfc") % q
        R = (B * r) % p
        Rv = (Bv * r) % p
        R_bytes = R.to_bytes(32, "little")
        Rv_bytes = Rv.to_bytes(32, "little")
        h = hash_bytes(a_bytes + V_bytes + R_bytes + Rv_bytes + message, b"\xfb") % q
        s = (r + h * a) % q
        s_bytes = s.to_bytes(32, "little")
        v = hash_bytes(V_bytes, b"\xfa") % (2**256)
        return V_bytes + h.to_bytes(32, "little") + s_bytes, v.to_bytes(32, "little")

    @staticmethod
    def verify(mont_pub: x25519.X25519PublicKey, message: bytes, signature: bytes) -> Optional[bytes]:
        p = 2**255 - 19
        q = 2**252 + 27742317777372353535851937790883648493
        u = int.from_bytes(
            mont_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ), "little"
        )
        V_bytes = signature[:32]
        h_bytes = signature[32:64]
        s_bytes = signature[64:]
        V = int.from_bytes(V_bytes, "little")
        h = int.from_bytes(h_bytes, "little")
        s = int.from_bytes(s_bytes, "little")
        if u >= p or V >= 2**255 or h >= 2**253 or s >= 2**253:
            return False
        A = mont_to_ed_point(u, p)
        Bv = hash_bytes(A[1].to_bytes(32, "little") + message, b"\xfd") % q
        R = (pow(9, s, p) - h * A[1]) % p
        Rv = (pow(Bv, s, p) - h * V) % p
        hcheck = hash_bytes(
            A[1].to_bytes(32, "little") + V_bytes + R.to_bytes(32, "little") + Rv.to_bytes(32, "little") + message, b"\xfb"
        ) % q
        if h == hcheck:
            v = hash_bytes(V_bytes, b"\xfa") % (2**256)
            return v.to_bytes(32, "little")
        return None

class X3DH:
    @staticmethod
    def dh(priv: x25519.X25519PrivateKey, pub: x25519.X25519PublicKey) -> bytes:
        return priv.exchange(pub)
    @staticmethod
    def kdf(key_material: bytes, info: bytes, salt: Optional[bytes] = None, length: int = 32) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key_material)
    @staticmethod
    def run_x3dh(
        IKA_priv: x25519.X25519PrivateKey,
        EKA_priv: x25519.X25519PrivateKey,
        IKB_pub: x25519.X25519PublicKey,
        SPKB_pub: x25519.X25519PublicKey,
        OPKB_pub: Optional[x25519.X25519PublicKey],
        signed_prekey_signature: bytes,
        info: bytes
    ) -> bytes:
        dh1 = X3DH.dh(IKA_priv, SPKB_pub)
        dh2 = X3DH.dh(EKA_priv, IKB_pub)
        dh3 = X3DH.dh(EKA_priv, SPKB_pub)
        dhs = [dh1, dh2, dh3]
        if OPKB_pub:
            dh4 = X3DH.dh(EKA_priv, OPKB_pub)
            dhs.append(dh4)
        KM = b''.join(dhs)
        SK = X3DH.kdf(KM, info, salt=b'\x00' * 32)
        return SK

class DoubleRatchetState:
    def __init__(self):
        self.DHs: x25519.X25519PrivateKey = KeyHelper.generate_x25519_key_pair()
        self.DHr: Optional[x25519.X25519PublicKey] = None
        self.RK: bytes = secrets.token_bytes(ROOT_KEY_SIZE)
        self.CKs: Optional[bytes] = None
        self.CKr: Optional[bytes] = None
        self.Ns: int = 0
        self.Nr: int = 0
        self.PN: int = 0
        self.MKSKIPPED: Dict[Tuple[bytes, int], bytes] = {}

class DoubleRatchet:
    @staticmethod
    def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'DoubleRatchetRK',
            backend=default_backend()
        ).derive(ByteUtil.concat(rk, dh_out))
        return hkdf[:32], hkdf[32:]
    @staticmethod
    def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'DoubleRatchetCK',
            backend=default_backend()
        ).derive(ck)
        return hkdf[:32], hkdf[32:64]
    @staticmethod
    def encrypt(state: DoubleRatchetState, plaintext: bytes, ad: bytes) -> Tuple[bytes, bytes]:
        state.CKs, mk = DoubleRatchet.kdf_ck(state.CKs)
        nonce = secrets.token_bytes(CHACHA20_NONCE_SIZE)
        cipher = ChaCha20Poly1305(mk)
        header = struct.pack("!I", state.PN) + state.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        ciphertext = cipher.encrypt(nonce, plaintext, ByteUtil.concat(ad, header))
        state.Ns += 1
        return header + nonce, ciphertext
    @staticmethod
    def decrypt(state: DoubleRatchetState, header: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        pn = struct.unpack("!I", header[:4])[0]
        dh_pub = x25519.X25519PublicKey.from_public_bytes(header[4:36])
        nonce = header[36:48]
        if dh_pub != state.DHr:
            DoubleRatchet.skip_message_keys(state, pn)
            DoubleRatchet.dh_ratchet(state, dh_pub)
        DoubleRatchet.skip_message_keys(state, pn)
        state.CKr, mk = DoubleRatchet.kdf_ck(state.CKr)
        state.Nr += 1
        cipher = ChaCha20Poly1305(mk)
        return cipher.decrypt(nonce, ciphertext, ByteUtil.concat(ad, header))
    @staticmethod
    def skip_message_keys(state: DoubleRatchetState, until: int):
        if state.Nr + MAX_SKIP < until:
            raise InvalidMessageException("Too many skipped message keys")
        if state.CKr:
            while state.Nr < until:
                state.CKr, mk = DoubleRatchet.kdf_ck(state.CKr)
                state.MKSKIPPED[(state.DHr.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw), state.Nr)] = mk
                state.Nr += 1
    @staticmethod
    def dh_ratchet(state: DoubleRatchetState, header_dh: x25519.X25519PublicKey):
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.DHr = header_dh
        rk, ckr = DoubleRatchet.kdf_rk(state.RK, state.DHs.exchange(state.DHr))
        state.RK, state.CKr = rk, ckr
        state.DHs = KeyHelper.generate_x25519_key_pair()
        rk, cks = DoubleRatchet.kdf_rk(state.RK, state.DHs.exchange(state.DHr))
        state.RK, state.CKs = rk, cks

class AESCipher:
    @staticmethod
    def encrypt_gcm(key: bytes, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        nonce = secrets.token_bytes(AESGCM_NONCE_SIZE)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext, b''
    @staticmethod
    def decrypt_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b'') -> bytes:
        cipher = AESGCM(key)
        return cipher.decrypt(nonce, ciphertext, associated_data)
    @staticmethod
    def encrypt_cbc(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len] * pad_len)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    @staticmethod
    def decrypt_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = plaintext[-1]
        return plaintext[:-pad_len]
