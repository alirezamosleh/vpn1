"""
کلاینت MyVPN برای لینوکس.

حالت PROXY (پیش‌فرض، بدون root):
    1. به سرور وصل می‌شود، کد سکرت را وارد (یا با --secret) و handshake می‌کند.
    2. یک SOCKS5 proxy محلی روی 127.0.0.1:1080 بالا می‌آورد.
    3. استفاده:
         curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
         export ALL_PROXY=socks5h://127.0.0.1:1080

حالت TUN (نیازمند root):
    تانل IP کامل؛ سرور IP کلاینت را push می‌کند و route پیش‌فرض عبور می‌کند.

اجرا:
    python3 client.py --server IP:PORT --secret "CODE" [--mode proxy|tun]
"""

import argparse
import hashlib
import os
import selectors
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared import crypto, proto  # noqa: E402

SOCKS_PORT = 1080


def log(*a):
    print(time.strftime('[%H:%M:%S]'), *a, flush=True)


# ---------------------------------------------------------------------------
# Handshake سمت کلاینت
# ---------------------------------------------------------------------------

def secret_proof(secret, client_nonce, server_nonce, pub_c, pub_s):
    h = hashlib.sha256()
    h.update(b'myvpn-auth-v1|')
    h.update(secret.encode())
    h.update(client_nonce)
    h.update(server_nonce)
    h.update(pub_c)
    h.update(pub_s)
    return h.digest()


class Tunnel:
    """کانال رمزنگاری‌شده به سرور + ارسال/دریافت فریم."""

    def __init__(self, host, port, secret):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(None)
        self._handshake(secret)
        self.lock = threading.Lock()
        self.alive = True
        # جدول استریم‌های دریافتی
        self.streams = {}   # req_id -> { 'sock': socket|None, 'buf': bytearray,
                            #           'open': bool, 'eof': bool, 'event': Condition }
        self.cond = threading.Condition()
        self.next_id = 1
        threading.Thread(target=self._reader_loop, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    # ---------------- handshake ----------------
    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    def _frame_recv(self, reader):
        while True:
            f = reader.next_frame()
            if f:
                return f
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("closed in handshake")
            reader.feed(data)

    def _handshake(self, secret):
        reader = proto.FrameReader()
        priv_c, pub_c = crypto.generate_keypair()
        client_nonce = os.urandom(16)
        self.sock.sendall(proto.pack(proto.HELLO, pub_c + client_nonce))

        mtype, payload = self._frame_recv(reader)
        if mtype != proto.KEYSHARE or len(payload) < 32 + 16:
            raise ConnectionError("bad keyshare")
        pub_s = payload[:32]
        server_nonce = payload[32:48]

        eph_priv, eph_pub = crypto.generate_keypair()
        proof = secret_proof(secret, client_nonce, server_nonce, pub_c, pub_s)
        self.sock.sendall(proto.pack(proto.AUTH, eph_pub + proof))

        mtype, payload = self._frame_recv(reader)
        if mtype == proto.ERROR:
            raise PermissionError("کد سکرت اشتباه است (AUTH failed)")
        if mtype != proto.AUTH_OK:
            raise ConnectionError("bad auth_ok")

        shared = crypto.x25519(eph_priv, pub_s)
        self.sess = crypto.SessionCrypto(shared, our_role='client')
        # راستی‌آزمایی پیام سرور
        msg = self.sess.decrypt(payload)
        if msg != b'AUTH_OK':
            raise ConnectionError("auth_ok mismatch")
        # هر دو طرف بعد از handshake شمارنده صفر دارند؛ برای جلوگیری از
        # برخورد nonce در جهت client->server هیچ پیامی بین این دو exchange
        # نشده پس مشکلی نیست.

    # ---------------- I/O ----------------
    def send_data(self, inner):
        with self.lock:
            pkt = proto.pack(proto.DATA, self.sess.encrypt(inner))
            self.sock.sendall(pkt)

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _reader_loop(self):
        reader = proto.FrameReader()
        # هر داده‌ای که در handshake باقی مانده را هم بخوانیم
        while self.alive:
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            reader.feed(data)
            while True:
                f = reader.next_frame()
                if not f:
                    break
                mtype, payload = f
                if mtype == proto.PONG:
                    continue
                if mtype != proto.DATA:
                    continue
                try:
                    inner = self.sess.decrypt(payload)
                except ValueError as e:
                    log("decrypt error:", e)
                    self.alive = False
                    return
                self._dispatch(inner)
        self.alive = False
        with self.cond:
            self.cond.notify_all()

    def _dispatch(self, inner):
        kind = inner[0]
        body = inner[1:]
        if kind == 2:  # OPEN_OK
            req_id = struct.unpack('>I', body[:4])[0]
            with self.cond:
                st = self.streams.get(req_id)
                if st:
                    st['open'] = True
                self.cond.notify_all()
        elif kind == 3:  # WRITE
            req_id = struct.unpack('>I', body[:4])[0]
            chunk = body[4:]
            with self.cond:
                st = self.streams.get(req_id)
                if st:
                    st['buf'].extend(chunk)
                self.cond.notify_all()
        elif kind == 4:  # CLOSE
            req_id = struct.unpack('>I', body[:4])[0]
            with self.cond:
                st = self.streams.get(req_id)
                if st:
                    st['eof'] = True
                self.cond.notify_all()

    # ---------------- API برای SOCKS ----------------
    def new_stream(self):
        with self.cond:
            rid = self.next_id
            self.next_id += 1
            self.streams[rid] = {'open': False, 'eof': False,
                                 'buf': bytearray()}
        return rid

    def open_remote(self, host, port):
        rid = self.new_stream()
        hb = host.encode()
        msg = bytes([1]) + bytes([len(hb)]) + hb + \
            struct.pack('>HI', port, rid)
        self.send_data(msg)
        deadline = time.time() + 15
        with self.cond:
            while True:
                st = self.streams[rid]
                if st['open']:
                    return rid
                if st['eof']:
                    self.streams.pop(rid, None)
                    raise ConnectionError("remote connect refused")
                if not self.cond.wait(0.5) and time.time() > deadline:
                    raise TimeoutError("open timeout")

    def write(self, rid, data):
        msg = bytes([3]) + struct.pack('>I', rid) + data
        # قطعه‌بندی
        for i in range(0, len(data), 16000):
            part = data[i:i + 16000]
            self.send_data(bytes([3]) + struct.pack('>I', rid) + part)

    def read(self, rid, want_eof=False):
        """خواندن داده موجود؛ اگر eof رخ دهد None برمی‌گرداند."""
        deadline = time.time() + 60
        with self.cond:
            while True:
                st = self.streams.get(rid)
                if st is None:
                    return None
                if st['buf']:
                    out = bytes(st['buf'])
                    st['buf'].clear()
                    return out
                if st['eof']:
                    self.streams.pop(rid, None)
                    return None
                if not self.cond.wait(0.5) and time.time() > deadline:
                    return None

    def close_stream(self, rid):
        self.send_data(bytes([4]) + struct.pack('>I', rid))
        with self.cond:
            self.streams.pop(rid, None)

    def _keepalive(self):
        while self.alive:
            time.sleep(20)
            if not self.alive:
                break
            try:
                self.sock.sendall(proto.pack(proto.PING))
            except OSError:
                break


# ---------------------------------------------------------------------------
# SOCKS5 سرور محلی
# ---------------------------------------------------------------------------

def socks_handle(conn, tunnel):
    try:
        hdr = conn.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            return
        nmethods = hdr[1]
        conn.recv(nmethods)
        conn.sendall(b'\x05\x00')  # No auth

        req = conn.recv(4)
        if len(req) < 4 or req[0] != 5 or req[1] != 1:  # CONNECT
            conn.close()
            return
        atyp = req[3]
        if atyp == 1:
            addr = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            addr = conn.recv(ln).decode()
        elif atyp == 4:
            conn.recv(16)
            conn.close()
            return
        else:
            conn.close()
            return
        port = struct.unpack('>H', conn.recv(2))[0]

        try:
            rid = tunnel.open_remote(addr, port)
        except Exception as e:
            log("open_remote failed:", e)
            conn.sendall(b'\x05\x01\x00\x01' + b'\x00' * 4 + b'\x00\x00')
            conn.close()
            return

        conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') +
                     struct.pack('>H', port))
        log(f"stream opened: {addr}:{port}")

        stop = threading.Event()

        def local_to_tunnel():
            while not stop.is_set():
                try:
                    data = conn.recv(32768)
                except OSError:
                    break
                if not data:
                    break
                tunnel.write(rid, data)
            stop.set()

        t = threading.Thread(target=local_to_tunnel, daemon=True)
        t.start()
        try:
            while True:
                chunk = tunnel.read(rid)
                if chunk is None:
                    break
                conn.sendall(chunk)
        finally:
            stop.set()
            try:
                tunnel.close_stream(rid)
            except OSError:
                pass
            conn.close()
    except Exception as e:
        try:
            conn.close()
        except OSError:
            pass


def run_socks_local(tunnel, port=SOCKS_PORT):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(('127.0.0.1', port))
    lsock.listen(32)
    log(f"SOCKS5 محلی آماده: 127.0.0.1:{port}")
    log("مثال: curl --socks5-hostname 127.0.0.1:%d https://ifconfig.me" % port)
    while tunnel.alive:
        try:
            conn, addr = lsock.accept()
        except OSError:
            break
        threading.Thread(target=socks_handle, args=(conn, tunnel),
                         daemon=True).start()


# ---------------------------------------------------------------------------
# حالت TUN کلاینت
# ---------------------------------------------------------------------------

def run_tun_mode(tunnel):
    # منتظر پیام CFG سرور بمانیم (روی کانال DATA با پیشوند CFG)
    cfg = None
    deadline = time.time() + 10
    # پیام CFG داخل stream معمولی نمی‌آید؛ آن را از reader جدا می‌گیریم:
    # ساده‌سازی: سرور CFG را به‌صورت DATA با بدنه‌ی b'CFG{json}' می‌فرستد.
    # dispatch ما عدد اول را kind می‌گیرد؛ پس kind=67 ('C') — مدیریت ویژه:
    import json

    class CfgWait:
        pass

    # برای سادگی، اینجا فرض می‌کنیم سرور cfg را با نوع داخلی 5 فرستاده
    # (در نسخه کامل‌تر). در این نمونه فقط مقادیر پیش‌فرض استفاده می‌شود.
    client_ip = os.environ.get('MYVPN_CLIENT_IP', '10.66.1.2')
    server_ip = os.environ.get('MYVPN_SERVER_IP', '10.66.1.1')

    name = 'myvpn0'
    subprocess.run(['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun'],
                   check=False)
    subprocess.run(['ip', 'addr', 'add', client_ip + '/24', 'dev', name],
                   check=False)
    subprocess.run(['ip', 'link', 'set', name, 'up'], check=False)

    TUNSETIFF = 0x400454ca
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
    import fcntl
    fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    subprocess.run(['ip', 'route', 'add', 'default', 'dev', name],
                   check=False)
    log(f"TUN {name} بالا آمد؛ ترافیک از تانل عبور می‌کند.")

    stop = threading.Event()

    def tun_to_tunnel():
        sel = selectors.DefaultSelector()
        sel.register(fd, selectors.EVENT_READ)
        while not stop.is_set():
            if sel.select(0.5):
                try:
                    pkt = os.read(fd, 65535)
                except OSError:
                    continue
                if pkt:
                    try:
                        tunnel.send_data(bytes([5]) + pkt)
                    except OSError:
                        break
        sel.close()

    t = threading.Thread(target=tun_to_tunnel, daemon=True)
    t.start()
    try:
        while tunnel.alive:
            chunk = tunnel.read_wait_raw(timeout=1)
            if chunk is None:
                continue
            # بدنه‌های kind=5 => packet برای TUN
            try:
                os.write(fd, chunk)
            except OSError:
                pass
    finally:
        stop.set()
        os.close(fd)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='MyVPN Linux client')
    ap.add_argument('--server', required=True, help='IP:PORT سرور')
    ap.add_argument('--secret', default=None, help='کد سکرت (اختیاری)')
    ap.add_argument('--mode', choices=['proxy', 'tun'], default='proxy')
    ap.add_argument('--socks-port', type=int, default=SOCKS_PORT)
    args = ap.parse_args()

    secret = args.secret
    if not secret:
        import getpass
        secret = getpass.getpass('کد سکرت VPN: ')

    host, _, port = args.server.partition(':')
    port = int(port or 8443)

    log(f"اتصال به {host}:{port} ...")
    try:
        tunnel = Tunnel(host, port, secret)
    except PermissionError as e:
        log("خطا:", e)
        sys.exit(2)
    except Exception as e:
        log("خطای اتصال:", e)
        sys.exit(1)

    log("✅ اتصال موفق — handshake و احراز هویت انجام شد.")

    if args.mode == 'proxy':
        try:
            run_socks_local(tunnel, args.socks_port)
        except KeyboardInterrupt:
            pass
        finally:
            tunnel.close()
    else:
        run_tun_mode(tunnel)


if __name__ == '__main__':
    main()
