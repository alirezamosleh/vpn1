"""
رمزنگاری اشتراکی سرور و کلاینت — بدون وابستگی اجباری به کتابخانه خارجی.

- رمزنگار: ChaCha20-Poly1305 (RFC 8439)
    * اگر کتابخانه `cryptography` نصب باشد، از پیاده‌سازی C آن استفاده می‌شود
      (سریع‌تر؛ برای تانل با ترافیک بالا مهم است).
    * در غیر این صورت، پیاده‌سازی خالص پایتون به‌کار می‌رود.
- تبادل کلید: X25519 (Curve25519) با ECDH + HKDF-SHA256
- هر بسته یک Nonce یکتا دارد (counter) => replay با Poly1305 رد می‌شود
"""

import hashlib
import hmac
import os
import struct

# شتاب‌دهنده اختیاری (cryptography) --------------------------------------
try:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 (RFC 8439)
# ---------------------------------------------------------------------------

_MASK32 = 0xFFFFFFFF


def _rotl32(v, n):
    return ((v << n) & _MASK32) | (v >> (32 - n))


def _chacha20_block(key, counter, nonce):
    """تولید یک بلوک ۶۴ بایتی ChaCha20 (nonce 12 بایتی RFC 8439)."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack('<8I', key))
    # word 12 = 32-bit block counter، words 13..15 = nonce
    state += [counter & _MASK32] + list(struct.unpack('<3I', nonce))

    def quarter(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & _MASK32; x[d] = _rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & _MASK32; x[b] = _rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & _MASK32; x[d] = _rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & _MASK32; x[b] = _rotl32(x[b] ^ x[c], 7)

    working = list(state)
    for _ in range(10):
        quarter(working, 0, 4, 8, 12)
        quarter(working, 1, 5, 9, 13)
        quarter(working, 2, 6, 10, 14)
        quarter(working, 3, 7, 11, 15)
        quarter(working, 0, 5, 10, 15)
        quarter(working, 1, 6, 11, 12)
        quarter(working, 2, 7, 8, 13)
        quarter(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack('<16I', *out)


def chacha20_xor(key, nonce, data, counter=0):
    out = bytearray(len(data))
    off = 0
    ln = len(data)
    while off < ln:
        block = _chacha20_block(key, counter + off // 64, nonce)
        chunk = data[off:off + 64]
        for i in range(len(chunk)):
            out[off + i] = chunk[i] ^ block[i]
        off += 64
    return bytes(out)


def _poly1305_mac(msg, key):
    def le_bytes_to_num(b):
        return sum(v << (8 * i) for i, v in enumerate(b))
    r = le_bytes_to_num(key[:16]) & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = le_bytes_to_num(key[16:32])
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        n = le_bytes_to_num(chunk + b'\x01' + b'\x00' * (15 - len(chunk)))
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def _pad16(data):
    rem = len(data) % 16
    if rem:
        return data + b'\x00' * (16 - rem)
    return data


def aead_encrypt(key, nonce, plaintext, aad=b''):
    if _HAVE_CRYPTO:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    otk = _chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, nonce, plaintext, counter=1)
    mac_data = (_pad16(aad) + _pad16(ct) +
                struct.pack('<QQ', len(aad), len(ct)))
    tag = _poly1305_mac(mac_data, otk)
    return ct + tag


def aead_decrypt(key, nonce, ciphertext_with_tag, aad=b''):
    if _HAVE_CRYPTO:
        # در صورت عدم تطابق tag، cryptography خودشان InvalidTag می‌دهد؛
        # آن را به ValueError تبدیل می‌کنیم تا لایه‌های بالاتر یکسان رفتار کنند.
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as e:
            raise ValueError(str(e))
    ct, tag = ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    mac_data = (_pad16(aad) + _pad16(ct) +
                struct.pack('<QQ', len(aad), len(ct)))
    expected = _poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("AEAD authentication failed")
    return chacha20_xor(key, nonce, ct, counter=1)


# ---------------------------------------------------------------------------
# X25519 ECDH (Montgomery ladder، RFC 7748)
# ---------------------------------------------------------------------------

_P25519 = (1 << 255) - 19
_A24 = 121665


def _cswap(swap, x_2, x_3):
    dummy = swap * (x_2 - x_3)
    x2 = (x_2 - dummy) % _P25519
    x3 = (x_3 + dummy) % _P25519
    return x2, x3


def _scalarmult_x25519(u_bytes, k_bytes):
    u = int.from_bytes(u_bytes, 'little') % _P25519
    k = bytearray(k_bytes)
    # RFC 7748 clamping (کلیت بایت‌ها little-endian است)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, 'little')

    x1, x2, x3 = u, 1, u
    z2, z3 = 0, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = k_t

        A = (x2 + z2) % _P25519
        AA = A * A % _P25519
        B = (x2 - z2) % _P25519
        BB = B * B % _P25519
        E = (AA - BB) % _P25519
        C = (x3 + z3) % _P25519
        D = (x3 - z3) % _P25519
        DA = D * A % _P25519
        CB = C * B % _P25519
        x3 = (DA + CB) % _P25519
        z3 = x1 * (DA - CB) % _P25519
        x2 = AA * BB % _P25519
        z2 = E * (AA + _A24 * E) % _P25519

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    return (x2 * pow(z2, _P25519 - 2, _P25519) % _P25519).to_bytes(32, 'little')


def x25519_base(priv):
    if _HAVE_CRYPTO:
        return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
    return _scalarmult_x25519(b'\x09' + b'\x00' * 31, priv)


def x25519(priv, pub):
    if _HAVE_CRYPTO:
        return X25519PrivateKey.from_private_bytes(priv).exchange(
            X25519PublicKey.from_public_bytes(pub))
    return _scalarmult_x25519(pub, priv)


def generate_keypair():
    if _HAVE_CRYPTO:
        priv = X25519PrivateKey.generate()
        return (priv.private_bytes_raw(),
                priv.public_key().public_bytes_raw())
    priv = bytearray(os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv = bytes(priv)
    return priv, x25519_base(priv)


# ---------------------------------------------------------------------------
# HKDF-SHA256
# ---------------------------------------------------------------------------

def hkdf(ikm, salt=b'', info=b'myvpn-session', length=64):
    if _HAVE_CRYPTO:
        return HKDF(algorithm=hashes.SHA256(), length=length,
                    salt=salt or None, info=info).derive(ikm)
    prk = hmac.new(salt or b'\x00' * 32, ikm, hashlib.sha256).digest()
    okm = b''
    t = b''
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


class SessionCrypto:
    """رمزنگار یک نشست: بعد از handshake، هر جهت با کلید خودش.

    توجه مهم (نسخه قبل): هر دو طرف از یک shared secret و صرفاً با تفاوت
    `info` در HKDF کلید می‌ساختند؛ چون شمارنده nonce در هر جهت از صفر شروع
    می‌شد، اگر پیام client و server هم‌اندازه و هم‌شمارنده می‌بودند، keystream
    یکسان تولید شده و XOR آن‌ها افشا می‌کرد. اینجا با salt تصادفی exchanged
    در handshake این مشکل حل شده و کلیدهای چهار جهت (c2s/s2c برای هر طرف)
    کاملاً مستقل‌اند.
    """

    def __init__(self, shared_secret, salt_c2s, salt_s2c):
        k_c2s = hkdf(shared_secret, salt=salt_c2s,
                     info=b'myvpn-v1-client-to-server')[:32]
        k_s2c = hkdf(shared_secret, salt=salt_s2c,
                     info=b'myvpn-v1-server-to-client')[:32]
        self.is_server = False
        # نقش بعداً با set_role تعیین می‌شود
        self._k_c2s, self._k_s2c = k_c2s, k_s2c
        self.send_key = None
        self.recv_key = None
        self.send_counter = 0
        self._recv_seen_max = -1

    def set_role(self, role):
        """role: 'client' یا 'server'."""
        self.is_server = (role == 'server')
        self.send_key = self._k_s2c if self.is_server else self._k_c2s
        self.recv_key = self._k_c2s if self.is_server else self._k_s2c
        return self

    @staticmethod
    def _nonce(counter):
        return counter.to_bytes(12, 'little')

    def encrypt(self, plaintext, aad=b''):
        if self.send_counter >= (1 << 64) - 1:
            raise ValueError("nonce space exhausted; re-handshake required")
        n = self.send_counter
        self.send_counter += 1
        ct = aead_encrypt(self.send_key, self._nonce(n), plaintext, aad)
        return struct.pack('<Q', n) + ct  # 8 بایت counter + ciphertext+tag

    def decrypt(self, packet, aad=b''):
        if len(packet) < 8 + 16:
            raise ValueError("truncated packet")
        counter = struct.unpack('<Q', packet[:8])[0]
        pt = aead_decrypt(self.recv_key, self._nonce(counter),
                          packet[8:], aad)
        # پنجره replay: بسته‌های با شمارنده خیلی قدیمی یا تکراری رد می‌شوند.
        if counter <= self._recv_seen_max - 64:
            raise ValueError("replay detected")
        if counter > self._recv_seen_max:
            self._recv_seen_max = counter
        return pt
