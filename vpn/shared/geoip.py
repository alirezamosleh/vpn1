"""
مدیریت Geo-IP (بخش «ملاحظه جغرافیا» در MyVPN).

روی سرور:
  - تعیین کشور خودِ سرور از طریق سرویس‌های IP-API (چند منبع به‌ترتیب اعتبار،
    با fallback تا آخرین منبع).
  - تولید / ذخیره گزارش وضعیت (`status.json`) که کلاینت هنگام اتصال می‌خواند.

روی کلاینت:
  - تعیین کشور محلی کاربر (برای تشخیص «خروج از سانده» / sandbox شبکه).
  - مقایسه کشور کلاینت با کشور سرور:
      * اگر یکی بودند هشدار داده می‌شود (VPN بی‌فایده؛ ترافیک از همان کشور خارج می‌شود).
  - نمایش پرچم/نام کشور خروجی در بنر اتصال و در tray آیکون.

هیچ وابستگی خارجی ندارد؛ فقط urllib از استاندارد پایتون.
"""

import json
import os
import socket
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# منابع اطلاعات IP (همه رایگان، بدون API key)
# ---------------------------------------------------------------------------

_SOURCES = [
    # هر ورودی: (نام, الگوی URL, نحوه استخراج)
    ("ip-api.com", "http://ip-api.com/json/?fields=status,country,countryCode,city,lat,lon,query", "json"),
    ("ipinfo.io", "https://ipinfo.io/json", "json"),
    ("ipwho.is", "https://ipwho.is/", "json"),
]

_UA = "Mozilla/5.0 (X11; Linux x86_64) myvpn-client/1.0"


def _fetch(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def normalize_info(raw, source):
    """خروجی یکپارچه: {country, cc, city, lat, lon, ip, source}"""
    if not isinstance(raw, dict):
        return None
    d = {"source": source, "country": None, "cc": None,
         "city": None, "lat": None, "lon": None, "ip": None}
    if source == "ip-api.com":
        if raw.get("status") != "success":
            return None
        d.update(country=raw.get("country"), cc=raw.get("countryCode"),
                 city=raw.get("city"), lat=raw.get("latitude") or raw.get("lat"),
                 lon=raw.get("longitude") or raw.get("lon"),
                 ip=raw.get("query"))
    elif source == "ipinfo.io":
        loc = (raw.get("loc") or "").split(",")
        d.update(country=raw.get("country"), cc=raw.get("country"),
                 city=raw.get("city"),
                 lat=float(loc[0]) if len(loc) > 0 and loc[0] else None,
                 lon=float(loc[1]) if len(loc) > 1 and loc[1] else None,
                 ip=raw.get("ip"))
    elif source == "ipwho.is":
        if raw.get("success") is False:
            return None
        d.update(country=raw.get("country"), cc=raw.get("country_code"),
                 city=raw.get("city"), lat=raw.get("latitude"),
                 lon=raw.get("longitude"), ip=raw.get("ip"))
    if not d["cc"]:
        return None
    return d


def get_geo(timeout_per_source=6):
    """تعیین موقعیت جغرافیایی IP فعلی این ماشین. None در صورت عدم دسترسی."""
    for name, url, kind in _SOURCES:
        try:
            info = normalize_info(_fetch(url, timeout_per_source), name)
            if info:
                return info
        except Exception:
            continue
    return None


def geo_summary(info):
    if not info:
        return "نامشخص (عدم دسترسی به سرویس Geo)"
    bits = [f"{info['country']} ({info['cc']})"]
    if info.get("city"):
        bits.append(info["city"])
    if info.get("ip"):
        bits.append(info["ip"])
    return " | ".join(bits)


# ---------------------------------------------------------------------------
# جدول نام کشورها -> کلمه برای Tray tooltip و لاگ (فارسی ساده)
# ---------------------------------------------------------------------------

_FLAG = {
    "IR": "🇮🇷", "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "FR": "🇫🇷",
    "GB": "🇬🇧", "CA": "🇨🇦", "SE": "🇸🇪", "FI": "🇫🇮", "TR": "🇹🇷",
    "AE": "🇦🇪", "RU": "🇷🇺", "CN": "🇨🇳", "JP": "🇯🇵", "AU": "🇦🇺",
    "AT": "🇦🇹", "CH": "🇨🇭", "PL": "🇵🇱", "IT": "🇮🇹", "ES": "🇪🇸",
    "HK": "🇭🇰", "SG": "🇸🇬", "IN": "🇮🇳", "UA": "🇺🇦", "ARM": "🇦🇲",
}


def flag(cc):
    return _FLAG.get((cc or "").upper(), "🌐")


def same_country(a, b):
    return bool(a and b and a.get("cc") == b.get("cc"))


# ---------------------------------------------------------------------------
# فایل وضعیت سرور (سرور می‌نویسد، کلاینت می‌خواند)
# ---------------------------------------------------------------------------

def write_status(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_status(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def local_ip_hint():
    """IP لوکال را حدس می‌زند (برای لاگ)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()
