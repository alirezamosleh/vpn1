"""
کلاینت MyVPN برای لینوکس (نسخه CLI).

حالت PROXY (پیش‌فرض، بدون root):
    1. به سرور وصل می‌شود، کد سکرت را وارد (یا با --secret / MYVPN_SECRET)
       و handshake می‌کند.
    2. یک SOCKS5 محلی روی 127.0.0.1:1080 بالا می‌آورد.
    3. استفاده:
         curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
         export ALL_PROXY=socks5h://127.0.0.1:1080

حالت TUN (نیازمند root):
    تانل IP کامل؛ سرور تنظیمات (IP/DNS) را رمزنگاری‌شده push می‌کند،
    کلاینت TUN بالا می‌آورد، route پیش‌فرض را عوض می‌کند و در پایان
    همه‌چیز را برمی‌گرداند.

قابلیت‌های Geo:
    - بعد از اتصال، کشور/شهر خروجی سرور (فریم SERVER_INFO) نمایش داده می‌شود.
    - کشور محلی کاربر هم گرفته می‌شود؛ اگر با کشور سرور یکی بود هشدار داده
      می‌شود که VPN عملاً تأثیر جغرافیایی ندارد.
    - با --verify-exit بعد از بالا آمدن SOCKS، IP خروجی واقعی از طریق خود
      تانل چک می‌شود (https://ifconfig.me/ip یا ipinfo.io/ip).

اجرا:
    python3 client.py --server IP:8585 [--secret CODE] [--mode proxy|tun]
                      [--verify-exit] [--no-geo]
"""

import argparse
import hashlib
import json
import os
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared import crypto, proto, geoip  # noqa: E402

SOCKS_PORT = 1080
DEFAULT_SERVER_PORT = 8585


def log(*a):
    print(time.strftime('[%H:%M:%S]'), *a, flush=True)


# ---------------------------------------------------------------------------
# Handshake سمت کلاینت
# ---------------------------------------------------------------------------

def secret_proof(secret, client_nonce, server_nonce, pub_c, pub_s):
    h = hashlib.sha256()
    h.update(b'myvpn-auth-v2|')
    h.update(secret.encode())
    h.update(client_nonce)
    h.update(server_nonce)
    h.update(pub_c)
    h.update(pub_s)
    return h.digest()


class Tunnel:
    """کانال رمزنگاری‌شده به سرور + ارسال/دریافت فریم + streamها."""

    def __init__(self, host, port, secret):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(None)
        self.lock = threading.Lock()   # محافظ send_counter در برابر ریس
        self.alive = True
        self.server_info = None        # dict اطلاعات geo سرور
        self.streams = {}              # req_id -> {'open','eof','buf'}
        self.cond = threading.Condition()
        self.next_id = 1
        self._pending_cfg = []         # پیام‌های CFG حالت tun
        self._raw_packets = []         # بسته‌های IP بدون stream (حالت tun)
        self._early = []               # DATA های زودهنگام handshake
        self._handshake(secret)

    # ---------------- handshake ----------------
    def _frame_recv(self, reader, timeout=15):
        end = time.time() + timeout
        while True:
            f = reader.next_frame()
            if f:
                return f
            if time.time() > end:
                raise ConnectionError("handshake timeout")
            try:
                self.sock.settimeout(max(0.5, end - time.time()))
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            finally:
                self.sock.settimeout(None)
            if not data:
                raise ConnectionError("closed in handshake")
            reader.feed(data)

    def _handshake(self, secret):
        reader = proto.FrameReader()
        priv_c, pub_c = crypto.generate_keypair()
        client_nonce = os.urandom(16)
        self.sock.sendall(proto.pack(proto.HELLO, pub_c + client_nonce))

        mtype, payload = self._frame_recv(reader)
        if mtype == proto.ERROR:
            raise PermissionError("سرور ما را رد کرد: " +
                                  payload.decode('utf-8', 'replace'))
        if mtype != proto.KEYSHARE or len(payload) < 32 + 16 + 32:
            raise ConnectionError("bad keyshare")
        pub_s = payload[:32]
        server_nonce = payload[32:48]
        salt_c2s = payload[48:64]
        salt_s2c = payload[64:80]

        eph_priv, eph_pub = crypto.generate_keypair()
        proof = secret_proof(secret, client_nonce, server_nonce, pub_c, pub_s)
        self.sock.sendall(proto.pack(proto.AUTH, eph_pub + proof))

        mtype, payload = self._frame_recv(reader)
        if mtype == proto.ERROR:
            raise PermissionError("کد سکرت اشتباه است (AUTH failed)")
        if mtype != proto.AUTH_OK:
            raise ConnectionError("bad auth_ok")

        shared = crypto.x25519(eph_priv, pub_s)
        self.sess = crypto.SessionCrypto(shared, salt_c2s,
                                         salt_s2c).set_role('client')
        if self.sess.decrypt(payload) != b'AUTH_OK':
            raise ConnectionError("auth_ok mismatch")

        # SERVER_INFO و هر DATA زودهنگام ممکن است داخل همان recv ها آمده
        # باشد؛ از بافر reader بیرونشانیم تا در loop اصلی نسوزند.
        self._boot_reader = reader
        self._pump_boot_frames(final=False)
        # اگر هنوز کامل‌نشده مانده، چند recv کوتاه انجام دهیم (سرور باید
        # بلافاصله بعد از AUTH_OK بفرستد)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                self.sock.settimeout(0.5)
                data = self.sock.recv(65536)
            except socket.timeout:
                if self.server_info is not None:
                    break
                continue
            except OSError:
                break
            finally:
                self.sock.settimeout(None)
            if not data:
                break
            reader.feed(data)
            self._pump_boot_frames(final=False)
            if self.server_info is not None and not reader.buf:
                break
        self._pump_boot_frames(final=True)

        threading.Thread(target=self._reader_loop, daemon=True).start()
        threading.Thread(target=self._keepalive, daemon=True).start()

    def _pump_boot_frames(self, final=False):
        """فریم‌های بافر handshake را پردازش می‌کند:
        SERVER_INFO -> ذخیره، DATA -> صف _early، PONG/PING -> نادیده."""
        r = self._boot_reader
        while True:
            f = r.next_frame()
            if not f:
                break
            mtype, payload = f
            if mtype == proto.SERVER_INFO and self.server_info is None:
                try:
                    self.server_info = json.loads(self.sess.decrypt(payload))
                except ValueError:
                    self.server_info = {}
            elif mtype == proto.DATA:
                with self.lock:
                    try:
                        inner = self.sess.decrypt(payload)
                    except ValueError:
                        continue
                self._early.append(inner)

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
        reader = self._boot_reader   # ادامه همان بافر handshake (نیم‌بسته‌ها نسوزند)
        # DATA های زودهنگام handshake را dispatch کن (CFG تونل و ...)
        early, self._early = list(self._early), []
        for inner in early:
            self._dispatch(inner)
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
                with self.lock:
                    try:
                        inner = self.sess.decrypt(payload)
                    except ValueError as e:
                        log("decrypt error:", e)
                        self.alive = False
                        inner = None
                if inner is None:
                    return
                self._dispatch(inner)
        self.alive = False
        with self.cond:
            self.cond.notify_all()

    def _dispatch(self, inner):
        if not inner:
            return
        kind = inner[0]
        body = inner[1:]
        if kind == proto.OPEN_OK:
            rid = struct.unpack('>I', body[:4])[0]
            with self.cond:
                st = self.streams.get(rid)
                if st:
                    st['open'] = True
                self.cond.notify_all()
        elif kind == proto.WRITE:
            rid = struct.unpack('>I', body[:4])[0]
            chunk = body[4:]
            with self.cond:
                st = self.streams.get(rid)
                if st:
                    st['buf'].extend(chunk)
                else:
                    # داده برای stream بسته‌شده: دور بریز تا نشت حافظه نشود
                    pass
                self.cond.notify_all()
        elif kind == proto.CLOSE:
            rid = struct.unpack('>I', body[:4])[0]
            with self.cond:
                st = self.streams.get(rid)
                if st:
                    st['eof'] = True
                self.cond.notify_all()
        elif kind == proto.ERROR_STREAM:
            rid = struct.unpack('>I', body[:4])[0]
            rlen = body[4] if len(body) > 4 else 0
            reason = body[5:5 + rlen].decode('utf-8', 'replace')
            log(f"stream {rid} refused by server: {reason}")
            with self.cond:
                st = self.streams.get(rid)
                if st:
                    st['eof'] = True
                    st['error'] = reason
                self.cond.notify_all()
        elif kind == 6:  # CONFIG (حالت TUN)
            self._pending_cfg.append(body)
            with self.cond:
                self.cond.notify_all()
        else:
            # حالت TUN: بقیه بدنه‌ها مستقیماً IP packet هستند
            self._raw_packets.append(inner)
            with self.cond:
                self.cond.notify_all()

    # ---------------- API برای SOCKS ----------------
    def open_remote(self, host, port):
        with self.cond:
            rid = self.next_id
            self.next_id += 1
            self.streams[rid] = {'open': False, 'eof': False,
                                 'buf': bytearray(), 'error': None}
        hb = host.encode()
        msg = bytes([proto.OPEN]) + bytes([len(hb)]) + hb + \
            struct.pack('>HI', port, rid)
        self.send_data(msg)
        deadline = time.time() + 15
        with self.cond:
            while True:
                st = self.streams[rid]
                if st['open']:
                    return rid
                if st['eof']:
                    err = st.get('error')
                    self.streams.pop(rid, None)
                    raise ConnectionError(err or "remote connect refused")
                if not self.alive:
                    raise ConnectionError("tunnel closed")
                if not self.cond.wait(0.5) and time.time() > deadline:
                    raise TimeoutError("open timeout")

    def write(self, rid, data):
        for i in range(0, len(data), 16000):
            part = data[i:i + 16000]
            self.send_data(bytes([proto.WRITE]) + struct.pack('>I', rid) + part)

    def read(self, rid):
        """خواندن داده موجود؛ None در eof/بسته شدن."""
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
                if st['eof'] or not self.alive:
                    self.streams.pop(rid, None)
                    return None
                if not self.cond.wait(0.5) and time.time() > deadline:
                    return None

    def close_stream(self, rid):
        try:
            self.send_data(bytes([proto.CLOSE]) + struct.pack('>I', rid))
        except OSError:
            pass
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
    rid = None
    try:
        hdr = conn.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            conn.close()
            return
        nmethods = hdr[1]
        conn.recv(nmethods)
        conn.sendall(b'\x05\x00')  # No auth

        req = conn.recv(4)
        if len(req) < 4 or req[0] != 5 or req[1] != 1:  # فقط CONNECT
            conn.close()
            return
        atyp = req[3]
        if atyp == 1:
            addr = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            addr = conn.recv(ln).decode('utf-8', 'replace')
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
                try:
                    tunnel.write(rid, data)
                except OSError:
                    break
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
            tunnel.close_stream(rid)
            conn.close()
    except Exception:
        pass
    finally:
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
    lsock.close()


# ---------------------------------------------------------------------------
# Geo: بنر اتصال و راستی‌آزمایی خروجی
# ---------------------------------------------------------------------------

def print_geo_banner(tunnel, local_geo=None):
    info = tunnel.server_info
    if info and info.get('cc'):
        log(f"🌍 کشور خروجی ترافیک: {geoip.flag(info['cc'])} "
            f"{info.get('country', '?')} ({info['cc']})"
            + (f" — {info['city']}" if info.get('city') else "")
            + (f" | IP: {info['ip']}" if info.get('ip') else ""))
        if local_geo and geoip.same_country(local_geo, info):
            log("⚠️  هشدار: کشور سرور با کشور فعلی شما یکی است؛ "
                "این VPN موقعیت جغرافیایی شما را تغییر نمی‌دهد.")
    else:
        log("ℹ️  سرور اطلاعات geo ارسال نکرد (شاید آفلاین بوده است).")


def http_via_socks(host, path, socks_port=SOCKS_PORT):
    """درخواست HTTP/1.0 ساده از طریق SOCKS5 محلی — بدون کتابخانه."""
    s = socket.create_connection(('127.0.0.1', socks_port), timeout=10)
    # SOCKS5 handshake
    s.sendall(b'\x05\x01\x00')
    if s.recv(2) != b'\x05\x00':
        s.close()
        raise ConnectionError("socks auth failed")
    hb = host.encode()
    s.sendall(b'\x05\x01\x00' + bytes([3, len(hb)]) + hb + struct.pack('>H', 80))
    rep = s.recv(4)
    if len(rep) < 4 or rep[1] != 0:
        s.close()
        raise ConnectionError("socks connect failed")
    atyp = rep[3]
    ln = {1: 4, 3: None, 4: 16}.get(atyp)
    if atyp == 3:
        ln = s.recv(1)[0]
    s.recv(ln + 2)
    req = (f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
           f"User-Agent: myvpn-check/1.0\r\nConnection: close\r\n\r\n")
    s.sendall(req.encode())
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b'\r\n\r\n')
    return body.decode('utf-8', 'replace').strip()


def verify_exit(socks_port=SOCKS_PORT):
    """IP خروجی واقعی را از پشت تانل می‌خواند و کشورش را نشان می‌دهد."""
    for host, path in (("ifconfig.me", "/ip"), ("api.ipify.org", "/")):
        try:
            ip = http_via_socks(host, path, socks_port)
            if ip and len(ip) < 45 and ' ' not in ip.strip():
                log(f"✅ IP خروجی از طریق VPN: {ip.strip()}")
                return ip.strip()
        except Exception as e:
            log(f"verify via {host} failed:", e)
    return None


# ---------------------------------------------------------------------------
# حالت TUN کلاینت
# ---------------------------------------------------------------------------

def wait_cfg(tunnel, timeout=15):
    end = time.time() + timeout
    with tunnel.cond:
        while not tunnel._pending_cfg:
            remaining = end - time.time()
            if remaining <= 0:
                raise TimeoutError("منتظر CONFIG سرور ماندیم؛ خبری نشد. "
                                   "(آیا سرور در حالت --mode tun اجرا شده؟)")
            tunnel.cond.wait(min(0.5, remaining))
        body = tunnel._pending_cfg.pop(0)
    return json.loads(body[3:].decode())  # بدنه: b'CFG{json}'


def run_tun_mode(tunnel):
    import fcntl
    cfg = wait_cfg(tunnel)
    client_ip, server_ip, dns = (cfg['client_ip'], cfg['server_ip'],
                                 cfg.get('dns', '1.1.1.1'))
    name = 'myvpn0'

    def ip_cmd(*args, check=False):
        subprocess.run(['ip', *args], check=check,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ip_cmd('tuntap', 'add', 'dev', name, 'mode', 'tun')
    fd = os.open('/dev/net/tun', os.O_RDWR)
    TUNSETIFF = 0x400454ca
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # مسیر سرور را قبل از عوض کردن default route ثابت نگه دار تا تانل
    # به خودش حلقه نکند
    server_host = tunnel.sock.getpeername()[0]
    try:
        server_ip_route = socket.gethostbyname(server_host)
        ip_cmd('route', 'add', '-host', server_ip_route,
               'via', _gateway_of_default())
    except Exception:
        pass

    old_default = _current_default_route()
    ip_cmd('addr', 'add', client_ip + '/24', 'dev', name)
    ip_cmd('link', 'set', name, 'up')
    ip_cmd('route', 'add', 'default', 'dev', name)
    resolv_backup = _swap_dns(dns)
    log(f"TUN {name} بالا آمد؛ IP شما در تانل: {client_ip}، DNS: {dns}")

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
                        tunnel.send_data(pkt)   # بدون پیشوند => raw IP packet
                    except OSError:
                        break
        sel.close()

    t = threading.Thread(target=tun_to_tunnel, daemon=True)
    t.start()
    try:
        while tunnel.alive:
            deadline = time.time() + 1.0
            got = False
            with tunnel.cond:
                while not tunnel._raw_packets and tunnel.alive \
                        and time.time() < deadline:
                    tunnel.cond.wait(0.2)
                if tunnel._raw_packets:
                    pkt = tunnel._raw_packets.pop(0)
                    got = True
            if got:
                try:
                    os.write(fd, pkt)
                except OSError:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join(timeout=2)
        log("برگرداندن تنظیمات شبکه ...")
        ip_cmd('route', 'del', 'default', 'dev', name)
        if old_default:
            ip_cmd(*old_default)
        ip_cmd('link', 'set', name, 'down')
        ip_cmd('tuntap', 'del', 'dev', name, 'mode', 'tun')
        _restore_dns(resolv_backup)
        os.close(fd)


def _gateway_of_default():
    out = subprocess.check_output(['ip', 'route', 'show', 'default'],
                                  text=True)
    toks = out.split()
    if 'via' in toks:
        return toks[toks.index('via') + 1]
    raise RuntimeError("no default gateway")


def _current_default_route():
    try:
        out = subprocess.check_output(['ip', '-o', 'route', 'show',
                                       'default'], text=True)
        line = out.strip().split('\n')[0]
        return ['route', 'add'] + line.split()
    except Exception:
        return None


def _swap_dns(dns):
    """DNS موقت؛ backup برمی‌گرداند تا در finally restore شود."""
    backup = {'done': False, 'content': None}
    try:
        with open('/etc/resolv.conf') as f:
            backup['content'] = f.read()
        with open('/etc/resolv.conf', 'w') as f:
            f.write(f"nameserver {dns}\n")
        backup['done'] = True
    except OSError:
        log("نتوانستم DNS را عوض کنم (مجوز؟) — DNS فعلی می‌ماند.")
    return backup


def _restore_dns(backup):
    if backup and backup.get('done'):
        try:
            with open('/etc/resolv.conf', 'w') as f:
                f.write(backup['content'])
        except OSError:
            pass


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='MyVPN Linux client')
    ap.add_argument('--server', required=True, help='IP:PORT سرور')
    ap.add_argument('--secret', default=None,
                    help='کد سکرت (اگر ندهید از MYVPN_SECRET یا prompt خوانده می‌شود)')
    ap.add_argument('--mode', choices=['proxy', 'tun'], default='proxy')
    ap.add_argument('--socks-port', type=int, default=SOCKS_PORT)
    ap.add_argument('--verify-exit', action='store_true',
                    help='بعد از اتصال، IP خروجی را از پشت تانل چک کن')
    ap.add_argument('--no-geo', action='store_true',
                    help='تماس با سرویس‌های geo فراموش شود')
    args = ap.parse_args()

    secret = args.secret or os.environ.get('MYVPN_SECRET')
    if not secret:
        import getpass
        secret = getpass.getpass('کد سکرت VPN: ')

    host, _, port = args.server.partition(':')
    port = int(port or DEFAULT_SERVER_PORT)

    log(f"اتصال به {host}:{port} ...")
    try:
        tunnel = Tunnel(host, port, secret)
    except PermissionError as e:
        log("❌ خطا:", e)
        sys.exit(2)
    except Exception as e:
        log("❌ خطای اتصال:", e)
        sys.exit(1)

    log("✅ اتصال موفق — handshake و احراز هویت انجام شد.")

    local_geo = None
    if not args.no_geo:
        local_geo = geoip.get_geo()
        if local_geo:
            log(f"🏠 موقعیت فعلی شما: {geoip.flag(local_geo['cc'])} "
                f"{local_geo['country']} ({local_geo['cc']})")
        print_geo_banner(tunnel, local_geo)

    if args.mode == 'proxy':
        if args.verify_exit:
            verify_exit(args.socks_port)
        try:
            run_socks_local(tunnel, args.socks_port)
        except KeyboardInterrupt:
            pass
        finally:
            tunnel.close()
    else:
        if os.geteuid() != 0:
            log("❌ حالت TUN نیازمند root است (sudo).")
            sys.exit(3)
        run_tun_mode(tunnel)
        tunnel.close()


if __name__ == '__main__':
    main()
