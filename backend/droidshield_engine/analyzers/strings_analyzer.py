"""
تحليل النصوص الثابتة في التطبيق: URLs، نطاقات، IP، بريد، أوامر shell، مسارات، نصوص مُرمّزة،
ونصوص مشبوهة. لكل نتيجة نحفظ مصادرها (classes.dex، resources.arsc، assets/x.json...).

تحذير حول الدقة: استخراج النصوص بأنماط (regex) ينتج حتماً بعض النتائج الخاطئة
(مثلاً "1.2.3.4" قد يكون رقم إصدار لا عنوان IP). لذلك:
    - النطاقات المستقلة (خارج URL) تمر بفلتر يستبعد أسماء الحزم (com.example.app).
    - كل فئة لها حد أقصى، ومع كل نتيجة عدد مرات ظهورها ومصادرها للمراجعة.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import math
import re
from collections import Counter

from ..config import DEFAULT_CONTENT_LIMITS, ContentLimits
from ..core.budget import TimeBudget
from .api_catalog import SENSITIVE_APIS
from .base import BaseAnalyzer
from .dex_analyzer import descriptor_to_java

URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\^`{|}]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,24})\b")
# كل جزء 0-255 بلا أصفار بادئة ("00" أو "010" ليست IPv4 قياسياً، و ipaddress يرفضها).
# اكتُشف في Phase 9: النص "0.0.9.00" في تطبيق حقيقي كان يُسقط وحدتين كاملتين.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d.])")
HOST_RE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})")
PATH_RE = re.compile(r"(?<![\w/])/(?:data|sdcard|storage|system|proc|dev|mnt|sys|vendor|cache|sbin|acct)/[\w./-]*")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HEX_RE = re.compile(r"[0-9a-fA-F]{32,}")
CIPHER_RE = re.compile(
    r"^(AES|DES|DESede|TripleDES|RSA|Blowfish|RC4|ARCFOUR|ChaCha20|Elgamal|ECIES)(/\w+/[\w-]+)?$", re.I)

# أسماء الحزم المعكوسة (com.example.app) تبدو كنطاقات؛ نستبعدها إذا بدأ أول مقطع بـ TLD
# (لأن الاسم المعكوس يبدأ دائماً بالـ TLD) أو بجذر حزم Java/Android المعروفة
REVERSE_DNS_FIRST = {"com", "org", "net", "io", "de", "edu", "gov", "uk", "fr", "me", "co", "app", "dev",
                     "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik"}
COMMON_TLDS = {
    "com", "net", "org", "io", "info", "biz", "ru", "cn", "xyz", "top", "site", "online", "club", "me", "co",
    "de", "uk", "fr", "br", "in", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "su", "ir", "ua", "kz", "app",
    "dev", "cloud", "live", "tech", "store", "shop", "link", "click", "us", "ca", "au", "jp", "kr", "it",
    "es", "nl", "pl", "tr", "vn", "id", "eu", "ws", "to", "ly", "gg", "sa", "ae", "eg", "sy", "iq", "jo",
}
FILE_TLDS = {"png", "jpg", "jpeg", "gif", "webp", "xml", "json", "so", "dex", "js", "css", "html", "txt", "kt", "java"}

SHELL_PATTERNS = [re.compile(p) for p in (
    r"^\s*su(\s|$)", r"\bwhich\s+su\b", r"\bsh\s+-c\b", r"\bchmod\s+[0-7]{3,4}\b",
    r"\bpm\s+(install|uninstall|grant|disable|hide)\b", r"\bam\s+(start|broadcast|force-stop|startservice)\b",
    r"^\s*(getprop|setprop)\b", r"\bmount\s+-o\b", r"\bbusybox\b", r"\biptables\b",
    r"^\s*(/system/bin/)?reboot\s*$", r"\brm\s+-r?f\b", r"\blogcat\s+-", r"^\s*dumpsys\b", r"\bscreencap\b",
    r"\binput\s+(tap|swipe|keyevent|text)\b", r"\bkill\s+-9\b", r"\bsettings\s+put\b",
)]
SHELL_RE = re.compile("|".join(f"(?:{p.pattern})" for p in SHELL_PATTERNS))
MAX_COMMAND_WORDS = 15   # النص الأطول جملة بشرية (ترجمة/شرح) وليس أمراً، حتى لو ذكر مساراً
# معرّفات برمجية (camelCase) تطابق أبجدية Base64 شكلياً: actionBarOnMenuKeyEventPre28
IDENTIFIER_RE = re.compile(r"(?:[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|_)+")
BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# عناوين DNS عامة معروفة أرقامها كلها أحادية (حتى لا تُعلَّم كـ OID/إصدار)
KNOWN_SINGLE_DIGIT_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}

SUSPICIOUS = {
    "root_detection": ("/system/xbin/su", "/system/bin/su", "/sbin/su", "Superuser.apk", "eu.chainfire.supersu",
                       "com.topjohnwu.magisk", "test-keys", "com.noshufou.android.su"),
    "emulator_detection": ("goldfish", "ranchu", "ro.kernel.qemu", "generic_x86", "sdk_gphone", "Genymotion",
                           "/dev/qemu_pipe", "ro.hardware.virtual"),
    "sensitive_content_uri": ("content://sms", "content://mms", "content://call_log", "content://contacts",
                              "content://com.android.contacts", "content://browser/bookmarks"),
}
# أسماء أصناف حساسة مكتوبة كنص -> مؤشر على استدعائها عبر Reflection
REFLECTION_CLASS_NAMES = {descriptor_to_java(c) for rules in SENSITIVE_APIS.values() for c, _ in rules}
REFLECTION_METHOD_NAMES = {
    "sendTextMessage", "sendMultipartTextMessage", "getDeviceId", "getSubscriberId", "getSimSerialNumber",
    "getLine1Number", "getImei", "loadDex", "getInstalledPackages", "getInstalledApplications",
    "setComponentEnabledSetting", "lockNow", "wipeData", "performGlobalAction", "getLastKnownLocation",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def clean_url(url: str) -> str:
    return url.rstrip(".,;:)]}'\"")


def url_host(url: str) -> str | None:
    m = re.match(r"^[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", url, re.I)
    return m.group(1).lower() if m else None


def is_ambiguous_ip(ip: str, standalone: bool = True) -> bool:
    """
    نصوص تطابق شكل IPv4 لكنها غالباً ليست عناوين:
        - OID (معرّفات ASN.1 في مكتبات التشفير، مثل 2.5.29.14): حسب معيار X.660 يبدأ كل OID
          بـ 0 أو 1 أو 2، فنعلّم النص المستقل الذي يبدأ بها
        - رقم إصدار (1.2.2.1): كل الأجزاء أرقام أحادية
    نعلّمها ambiguous ولا نحذفها (قد تكون عنواناً حقيقياً). العنوان داخل URL ليس مبهماً.
    """
    if ip in KNOWN_SINGLE_DIGIT_IPS or not standalone:
        return False
    parts = ip.split(".")
    return parts[0] in ("0", "1", "2") or all(len(p) == 1 for p in parts)


def classify_ip(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.is_loopback:
        return "loopback"
    if a.is_private:
        return "private"
    if a.is_multicast or a.is_reserved or a.is_unspecified or a.is_link_local:
        return "reserved"
    return "public"


def is_plausible_domain(s: str) -> bool:
    m = HOST_RE.fullmatch(s)
    if not m:
        return False
    labels = s.split(".")
    return labels[0] not in REVERSE_DNS_FIRST and m.group(1) in COMMON_TLDS


class Findings:
    """مُجمِّع: لكل فئة -> قيمة -> {count, sources}. مع حد أقصى للقيم الفريدة."""

    def __init__(self, limits: ContentLimits):
        self.limits = limits
        self.data: dict[str, dict[str, dict]] = {}
        self.truncated: set[str] = set()

    def add(self, category: str, value: str, source: str, **extra) -> None:
        bucket = self.data.setdefault(category, {})
        item = bucket.get(value)
        if item is None:
            if len(bucket) >= self.limits.max_findings_per_category:
                self.truncated.add(category)
                return
            item = bucket[value] = {"value": value, "count": 0, "sources": [], **extra}
        item["count"] += 1
        if source not in item["sources"] and len(item["sources"]) < self.limits.max_sources_per_finding:
            item["sources"].append(source)

    def items(self, category: str) -> list[dict]:
        return sorted(self.data.get(category, {}).values(), key=lambda i: (-i["count"], i["value"]))


def add_ip(f: Findings, ip: str, source: str, in_url: bool = False, **extra) -> None:
    # دفاع إضافي: نص واحد غريب يجب ألا يُسقط وحدة كاملة
    try:
        scope = classify_ip(ip)
    except ValueError:
        return
    f.add("ip_addresses", ip, source, scope=scope,
          ambiguous=is_ambiguous_ip(ip, standalone=not in_url), in_url=in_url, **extra)


def scan_string(s: str, source: str, f: Findings) -> None:
    """
    يطبق كل الأنماط على نص واحد. دالة نقية على (نص، مصدر) لسهولة الاختبار.
    فحوصات سريعة ("://" in s، "@" in s...) قبل كل regex: معظم النصوص لا تحتاج أي regex.
    """
    if len(s) < 4:
        return
    has_url = "://" in s and URL_RE.search(s) is not None
    if has_url:
        for raw in URL_RE.findall(s):
            url = clean_url(raw)
            f.add("urls", url, source)
            host = url_host(url)
            if host:
                if IPV4_RE.fullmatch(host):
                    add_ip(f, host, source, in_url=True)
                else:
                    f.add("domains", host, source)
    elif "." in s:
        stripped = s.strip().lower()
        if is_plausible_domain(stripped):
            f.add("domains", stripped, source)
        for ip in IPV4_RE.findall(s):
            add_ip(f, ip, source)
    if "@" in s:
        for m in EMAIL_RE.finditer(s):
            if m.group(1).lower() not in FILE_TLDS:
                f.add("emails", m.group(0), source)
    if "/" in s:
        for p in PATH_RE.findall(s):
            f.add("file_paths", p.rstrip("."), source)
    if len(s.split()) <= MAX_COMMAND_WORDS and SHELL_RE.search(s):
        f.add("shell_commands", s.strip()[:300], source)
    for group, needles in SUSPICIOUS.items():
        for n in needles:
            if n in s:
                f.add("suspicious", n, source, group=group)
    st = s.strip()
    if st in REFLECTION_CLASS_NAMES or st in REFLECTION_METHOD_NAMES:
        f.add("suspicious", st, source, group="reflection_target")
    if CIPHER_RE.match(st):
        weak = bool(re.search(r"^(DES|RC4|ARCFOUR)\b|/ECB/", st, re.I))
        f.add("cipher_transformations", st, source, weak=weak)
    _encoded(st, source, f)


def looks_like_base64(s: str) -> bool:
    """
    الشكل وحده لا يكفي: معرّفات مثل OnCommandResultListener2 تطابق أبجدية Base64.
    نطلب: الطول مضاعف 4، أحرف كبيرة وصغيرة وأرقام، ليس معرّفاً برمجياً، وفيه + أو / أو =
    أو عشوائية عالية (entropy) كما في البيانات المرمّزة فعلاً.
    """
    if len(s) % 4 or not BASE64_RE.fullmatch(s) or s == BASE64_ALPHABET:
        return False
    if not (re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and re.search(r"\d", s)):
        return False
    # معرّف برمجي، أو مسار/تحويل تشفير من معرّفات (Elgamal/ECB/PKCS1Padding)
    if all(IDENTIFIER_RE.fullmatch(seg) for seg in s.split("/") if seg):
        return False
    return bool(re.search(r"[+/=]", s)) or shannon_entropy(s) >= 4.2


def _encoded(s: str, source: str, f: Findings) -> None:
    # hex أولاً: 3045AE6F... يطابق Base64 شكلياً لكنه hex (مفتاح/بصمة)
    if HEX_RE.fullmatch(s) and len(s) % 2 == 0 and not s.isdigit():
        f.add("hex_strings", s[:200], source, length=len(s))
    elif looks_like_base64(s):
        try:
            decoded = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            return
        text = decoded.decode("utf-8", "ignore")
        printable = sum(c.isprintable() for c in text) / max(len(text), 1)
        is_text = len(text) >= 4 and printable > 0.9
        f.add("base64_strings", s[:200], source, decoded_bytes=len(decoded),
              decoded_preview=text[:200] if is_text else None)
        if is_text:  # نص مخفي بـ Base64: نفحصه بحثاً عن روابط مخفية
            for url in URL_RE.findall(text):
                f.add("urls", clean_url(url), f"{source}:base64", hidden=True)


class StringsAnalyzer(BaseAnalyzer):
    name = "strings"

    def __init__(self, limits: ContentLimits = DEFAULT_CONTENT_LIMITS):
        self.limits = limits

    def analyze(self, apk) -> dict:
        budget = TimeBudget(self.limits.time_budget_seconds)
        f = Findings(self.limits)
        stats = {}
        for source, strings in apk.strings.items():
            if budget.exceeded():
                break
            entropies = []
            for i, s in enumerate(strings):
                if i % 2000 == 0 and budget.exceeded():
                    break
                scan_string(s, source, f)
                if len(s) >= 8:
                    entropies.append(shannon_entropy(s))
            stats[source] = {
                "strings": len(strings),
                "entropy_mean": round(sum(entropies) / len(entropies), 3) if entropies else 0.0,
                "high_entropy_ratio": round(sum(e > 4.5 for e in entropies) / len(entropies), 4) if entropies else 0.0,
            }

        categories = ["urls", "domains", "ip_addresses", "emails", "shell_commands", "file_paths",
                      "base64_strings", "hex_strings", "cipher_transformations", "suspicious"]
        out = {c: f.items(c) for c in categories}
        out.update({
            "counts": {c: len(out[c]) for c in categories},
            "sources": stats,
            "truncated": {"time_budget": budget.hit, "categories": sorted(f.truncated)},
            "elapsed_seconds": budget.elapsed,
        })
        return out
