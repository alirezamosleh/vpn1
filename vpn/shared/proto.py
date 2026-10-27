"""
پروتکل ساده MyVPN — بدون ردپای پروتکل‌های معروف (OpenVPN/WireGuard/SSH).

ساختار بسته روی TCP:
    [1 بایت نوع][2 بایت طول payload (big-endian)][payload]

نوع‌ها:
    0x01 HELLO      : پیشنهاد کلاینت + nonce تصادفی
    0x02 KEYSHARE   : پاسخ سرور با کلید عمومی X25519 + nonce
    0x03 AUTH       : اثبات کد سکرت (hash زنجیره‌ای) + کلید جلسه کلاینت
    0x04 AUTH_OK    : تأیید سرور
    0x05 DATA       : داده رمزنگاری‌شده ترافیک (IP tunnel یا proxy)
    0x06 PING / 0x07 PONG : نگه‌داشتن اتصال
    0xFF ERROR

چون همه بسته‌های DATA کاملاً رمزنگاری AEAD هستند و هدر ثابت چندبایتی دارند،
DPI نمی‌تواند این را به عنوان TLS یا پروتکل شناخته‌شده تطبیق دهد.
"""

import struct

HELLO = 0x01
KEYSHARE = 0x02
AUTH = 0x03
AUTH_OK = 0x04
DATA = 0x05
PING = 0x06
PONG = 0x07
SERVER_INFO = 0x08   # اطلاعات geo سرور (رمزنگاری‌شده بعد از احراز هویت)
ERROR = 0xFF

# انواع پیام داخلی روی کانال DATA (حالت proxy)
OPEN, OPEN_OK, WRITE, CLOSE, ERROR_STREAM = 1, 2, 3, 4, 5

MAX_PAYLOAD = 65535


def pack(msg_type, payload=b''):
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    return struct.pack('>BH', msg_type, len(payload)) + payload


class FrameReader:
    """خواننده استریم TCP که بسته‌به‌بسته تحویل می‌دهد."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data):
        self.buf.extend(data)

    def next_frame(self):
        """بازگرداندن (type, payload) یا None اگر کامل نیست."""
        if len(self.buf) < 3:
            return None
        mtype, ln = struct.unpack('>BH', self.buf[:3])
        if len(self.buf) < 3 + ln:
            return None
        payload = bytes(self.buf[3:3 + ln])
        del self.buf[:3 + ln]
        return mtype, payload
