"""
سرور MyVPN — دو حالت:

1) حالت TUN (پیش‌فرض): تانل IP کامل با TUN device.
   - ترافیک کلاینت از eth0 با NAT (masquerade) به بیرون می‌رود.
2) حالت PROXY (ساده، بدون نیاز به root/TUN):
   - سرور روی پورت VPN گوش می‌دهد؛ کلاینت بعد از اتصال، یک SOCKS5
     محلی روی 127.0.0.1:1080 بالا می‌آورد که ترافیکش از سرور خارج می‌شود.

اجرا:
    python3 server.py --secret "CODE" [--port 8443] [--mode proxy|tun]

نکته امنیتی: کد سکرت هرگز روی سیم رد و بدل نمی‌شود؛ فقط اثبات
knowledge (SHA-256 زنجیره‌ای روی nonceها) فرستاده می‌شود.
"""

import argparse
import hashlib
import hmac
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

DEFAULT_PORT = 8443
SESSION_TTL = 30  # ثانیه بی‌فعالیت تا قطع


def log(*a):
    print(time.strftime('[%H:%M:%S]'), *a, flush=True)


# ---------------------------------------------------------------------------
# Handshake مشترک
# ---------------------------------------------------------------------------

def secret_proof(secret, client_nonce, server_nonce, pub_c, pub_s):
    """اثبات کد سکرت بدون ارسال خودش."""
    h = hashlib.sha256()
    h.update(b'myvpn-auth-v1|')
    h.update(secret.encode())
    h.update(client_nonce)
    h.update(server_nonce)
    h.update(pub_c)
    h.update(pub_s)
    return h.digest()


def do_handshake_server(sock, secret):
    """انجام handshake سمت سرور. در موفقیت SessionCrypto برمی‌گرداند."""
    reader = proto.FrameReader()

    def recv_frame():
        while True:
            f = reader.next_frame()
            if f:
                return f
            data = sock.recv(4096)
            if not data:
                raise ConnectionError("closed during handshake")
            reader.feed(data)

    mtype, payload = recv_frame()
    if mtype != proto.HELLO or len(payload) < 32 + 16:
        sock.sendall(proto.pack(proto.ERROR, b'bad hello'))
        return None
    client_pub = payload[:32]
    client_nonce = payload[32:48]

    priv_s, pub_s = crypto.generate_keypair()
    server_nonce = os.urandom(16)
    sock.sendall(proto.pack(proto.KEYSHARE, pub_s + server_nonce))

    mtype, payload = recv_frame()
    if mtype != proto.AUTH or len(payload) < 32 + 32:
        sock.sendall(proto.pack(proto.ERROR, b'bad auth'))
        return None
    client_eph_pub = payload[:32]
    proof = payload[32:64]

    expected = secret_proof(secret, client_nonce, server_nonce,
                            client_pub, pub_s)
    if not hmac.compare_digest(expected, proof):
        log("AUTH failed from", sock.getpeername())
        sock.sendall(proto.pack(proto.ERROR, b'bad secret'))
        return None

    shared = crypto.x25519(priv_s, client_eph_pub)
    sess = crypto.SessionCrypto(shared, our_role='server')
    # یک پیام تأیید رمزنگاری‌شده بفرست تا کلاینت مطمئن شود سرور هم کلید دارد
    ok_payload = sess.encrypt(b'AUTH_OK')
    sock.sendall(proto.pack(proto.AUTH_OK, ok_payload))
    return sess


# ---------------------------------------------------------------------------
# حالت PROXY: کانال DATA <-> سوکت مقصد محلی (بدون TUN)
# ---------------------------------------------------------------------------

class ProxyServer:
    """
    پروتکل داخلی روی کانال رمزنگاری‌شده:
        [1 بایت نوع][payload]
        نوع 1: OPEN  -> host_len(1) host port(2) req_id(4)
        نوع 2: OPEN_OK -> req_id(4)
        نوع 3: WRITE -> req_id(4) data
        نوع 4: CLOSE -> req_id(4)
    """
    OPEN, OPEN_OK, WRITE, CLOSE = 1, 2, 3, 4

    def __init__(self, sess, sock, peer):
        self.sess = sess
        self.sock = sock
        self.peer = peer
        self.streams = {}  # req_id -> socket
        self.lock = threading.Lock()

    def _send(self, inner):
        try:
            self.sock.sendall(proto.pack(proto.DATA, self.sess.encrypt(inner)))
        except OSError:
            pass

    def handle(self):
        reader = proto.FrameReader()
        last = time.time()
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            last = time.time()
            reader.feed(data)
            while True:
                f = reader.next_frame()
                if not f:
                    break
                mtype, payload = f
                if mtype == proto.PING:
                    self.sock.sendall(proto.pack(proto.PONG))
                    continue
                if mtype != proto.DATA:
                    continue
                try:
                    inner = self.sess.decrypt(payload)
                except ValueError:
                    log("bad frame from", self.peer, "- dropping")
                    return
                self._dispatch(inner)
            if time.time() - last > SESSION_TTL * 6:
                break

    def _dispatch(self, inner):
        kind = inner[0]
        body = inner[1:]
        if kind == self.OPEN:
            hlen = body[0]
            host = body[1:1 + hlen].decode('utf-8', 'replace')
            port = struct.unpack('>H', body[1 + hlen:3 + hlen])[0]
            req_id = struct.unpack('>I', body[3 + hlen:7 + hlen])[0]
            try:
                remote = socket.create_connection((host, port), timeout=10)
                remote.setblocking(False)
                with self.lock:
                    self.streams[req_id] = remote
                self._send(struct.pack('>BI', self.OPEN_OK, req_id))
                threading.Thread(target=self._pump_remote,
                                 args=(req_id, remote), daemon=True).start()
            except OSError as e:
                # خطا را با CLOSE اعلام می‌کنیم
                self._send(struct.pack('>BI', self.CLOSE, req_id))

        elif kind == self.WRITE:
            req_id = struct.unpack('>I', body[:4])[0]
            chunk = body[4:]
            remote = self.streams.get(req_id)
            if remote:
                try:
                    remote.sendall(chunk)
                except OSError:
                    self._close_stream(req_id)

        elif kind == self.CLOSE:
            req_id = struct.unpack('>I', body[:4])[0]
            self._close_stream(req_id)

    def _close_stream(self, req_id):
        with self.lock:
            r = self.streams.pop(req_id, None)
        if r:
            try:
                r.close()
            except OSError:
                pass

    def _pump_remote(self, req_id, remote):
        sel = selectors.DefaultSelector()
        sel.register(remote, selectors.EVENT_READ)
        try:
            while True:
                events = sel.select(30)
                if not events:
                    continue
                try:
                    chunk = remote.recv(32768)
                except OSError:
                    chunk = b''
                if not chunk:
                    self._send(struct.pack('>BI', self.CLOSE, req_id))
                    self._close_stream(req_id)
                    return
                # قطعه‌بندی برای ماندن زیر MAX_PAYLOAD
                for i in range(0, len(chunk), 16000):
                    part = chunk[i:i + 16000]
                    self._send(struct.pack('>BI', self.WRITE, req_id) + part)
        finally:
            sel.close()


# ---------------------------------------------------------------------------
# حلقه اصلی سرور (selector، چند کلاینت همزمان)
# ---------------------------------------------------------------------------

class Server:
    def __init__(self, port, secret, mode):
        self.port = port
        self.secret = secret
        self.mode = mode
        self.clients = {}  # fd -> (sock, peer, ProxyServer|None, thread)

    def run(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind(('0.0.0.0', self.port))
        lsock.listen(16)
        log(f"MyVPN server listening on :{self.port} (mode={self.mode})")

        sel = selectors.DefaultSelector()
        sel.register(lsock, selectors.EVENT_READ)

        while True:
            for key, _ in sel.select(1):
                if key.fd == lsock.fileno():
                    self._accept(lsock, sel)
                else:
                    # در حالت proxy هر کلاینت thread خودش را دارد؛ اینجا فقط
                    # handshake اولیه در تhread انجام می‌شود
                    pass

    def _accept(self, lsock, sel):
        conn, addr = lsock.accept()
        conn.settimeout(15)
        log("connection from", addr)

        def serve():
            try:
                sess = do_handshake_server(conn, self.secret)
                if sess is None:
                    conn.close()
                    return
                log("client authenticated:", addr)
                if self.mode == 'proxy':
                    ps = ProxyServer(sess, conn, addr)
                    ps.handle()
                else:
                    self._serve_tun(sess, conn, addr)
            except Exception as e:
                log("client error:", e)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=serve, daemon=True).start()

    # ------------------- حالت TUN -------------------
    def _open_tun(self, name, ip):
        cmd = ['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun']
        subprocess.run(cmd, check=False)
        subprocess.run(['ip', 'addr', 'add', ip + '/24', 'dev', name],
                       check=False)
        subprocess.run(['ip', 'link', 'set', name, 'up'], check=False)
        TUNSETIFF = 0x400454ca
        IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
        fd = os.open('/dev/net/tun', os.O_RDWR)
        import fcntl
        ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        return fd

    def _setup_nat(self, tun_ip_cidr, ext_if):
        net = tun_ip_cidr  # e.g. 10.66.0.0/24
        subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                        '-s', net, '-o', ext_if, '-j', 'MASQUERADE'],
                       check=False)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'myvpn0',
                        '-j', 'ACCEPT'], check=False)
        subprocess.run(['iptables', '-A', 'FORWARD', '-o', 'myvpn0',
                        '-j', 'ACCEPT'], check=False)
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')

    def _serve_tun(self, sess, conn, addr):
        # یک TUN به ازای هر کلاینت (ساده‌سازی: شماره‌گذاری)
        Server._tun_counter = getattr(Server, '_tun_counter', 0) + 1
        n = Server._tun_counter
        name = f'myvpn{n}'
        client_ip = f'10.66.{n}.2'
        server_ip = f'10.66.{n}.1'
        fd = self._open_tun(name, server_ip)
        self._setup_nat(f'10.66.{n}.0/24', self._guess_ext_if())
        log(f"TUN {name} up; client route: give {client_ip} to peer via push")

        # ارسال تنظیمات به کلاینت (به صورت encrypt)
        cfg = json_dumps({'client_ip': client_ip, 'server_ip': server_ip,
                          'dns': '1.1.1.1'}).encode()
        conn.sendall(proto.pack(proto.DATA, sess.encrypt(b'CFG' + cfg)))

        import fcntl
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        stop = threading.Event()

        def tun_to_net():
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
                            conn.sendall(proto.pack(
                                proto.DATA, sess.encrypt(pkt)))
                        except OSError:
                            break
            sel.close()

        t = threading.Thread(target=tun_to_net, daemon=True)
        t.start()

        reader = proto.FrameReader()
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                reader.feed(data)
                while True:
                    f = reader.next_frame()
                    if not f:
                        break
                    mtype, payload = f
                    if mtype == proto.PING:
                        conn.sendall(proto.pack(proto.PONG))
                    elif mtype == proto.DATA:
                        try:
                            pt = sess.decrypt(payload)
                        except ValueError:
                            continue
                        if pt.startswith(b'CFG'):
                            continue
                        try:
                            os.write(fd, pt)
                        except OSError:
                            pass
        finally:
            stop.set()
            t.join(timeout=2)
            os.close(fd)

    @staticmethod
    def _guess_ext_if():
        try:
            out = subprocess.check_output(
                ['ip', 'route', 'show', 'default'], text=True)
            return out.split('dev')[1].split()[0]
        except Exception:
            return 'eth0'


def json_dumps(d):
    import json
    return json.dumps(d)


def main():
    ap = argparse.ArgumentParser(description='MyVPN custom server')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT)
    ap.add_argument('--secret', required=True, help='کد سکرت مشترک')
    ap.add_argument('--mode', choices=['proxy', 'tun'], default='proxy')
    args = ap.parse_args()

    s = Server(args.port, args.secret, args.mode)
    try:
        s.run()
    except KeyboardInterrupt:
        log("bye")


if __name__ == '__main__':
    main()
