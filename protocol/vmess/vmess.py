# vmess.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess — پیاده‌سازی بومی سرور (سمت inbound) مطابق اسپک رسمی v2fly/Xray
#
# منبع مرجع (خط‌به‌خط تطبیق داده شده):
#   - proxy/vmess/encoding/server.go   (DecodeRequestHeader / DecodeRequestBody /
#                                       EncodeResponseHeader / EncodeResponseBody)
#   - proxy/vmess/encoding/client.go   (GenerateChunkNonce — شمارنده ۱۶ بیتی BE
#                                       داخل ۲ بایت اول nonce)
#   - proxy/vmess/aead/encrypt.go      (Seal/OpenVMessAEADHeader)
#   - proxy/vmess/aead/authid.go       (CreateAuthID / Match)
#   - proxy/vmess/aead/kdf.go          (KDF زنجیره‌ای — بازسازی دقیق semantics
#                                       خاص crypto/hmac خود Go)
#   - proxy/vmess/aead/consts.go       (نام saltها)
#   - common/protocol/id.go            (cmdKey = MD5(uuid + ثابت c48619fe-…))
#   - common/protocol/headers.go       (SecurityType / RequestOption / Command)
#   - common/crypto/auth.go            (AuthenticationReader/Writer — فرمت chunk با
#                                       Shake-128 masking و padding)
#   - common/protocol/address.go       (PortThenAddress → اول پورت، بعد ATYP/آدرس)
#
# از نسخه‌ی ۲۰۲۲ به بعد (aeadForced=true) سرورهای xray/v2ray فقط هدر AEAD را
# می‌پذیرند و امنیت aes-128-gcm / chacha20-poly1305 را قبول می‌کنند؛ این ماژول
# دقیقاً همان مسیر مدرن را پیاده می‌کند.
# ══════════════════════════════════════════════════════════════════════════════

import hashlib
import secrets
import struct
import time
import zlib
from typing import Awaitable, Callable, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ── ثابت‌های پروتکل (از consts.go / headers.go / id.go) ────────────────────────
KDF_SALT_VMESS_AEAD_KDF       = "VMess AEAD KDF"
KDF_SALT_AUTH_ID_ENC_KEY      = "AES Auth ID Encryption"
KDF_SALT_HDR_PAYLOAD_KEY      = "VMess Header AEAD Key"
KDF_SALT_HDR_PAYLOAD_IV       = "VMess Header AEAD Nonce"
KDF_SALT_HDR_LEN_KEY          = "VMess Header AEAD Key_Length"
KDF_SALT_HDR_LEN_IV           = "VMess Header AEAD Nonce_Length"
KDF_SALT_RESP_HDR_LEN_KEY     = "AEAD Resp Header Len Key"
KDF_SALT_RESP_HDR_LEN_IV      = "AEAD Resp Header Len IV"
KDF_SALT_RESP_HDR_PAYLOAD_KEY = "AEAD Resp Header Key"
KDF_SALT_RESP_HDR_PAYLOAD_IV  = "AEAD Resp Header IV"

# cmdKey = MD5(uuid_bytes + این ثابت) — از common/protocol/id.go (NewID)
CMD_KEY_TAIL = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"

# SecurityType — از common/protocol/headers.pb.go
SEC_AES128_GCM        = 3
SEC_CHACHA20_POLY1305 = 4

# RequestOption — از common/protocol/headers.go
OPT_CHUNK_STREAM   = 0x01
OPT_CHUNK_MASKING  = 0x04
OPT_GLOBAL_PADDING = 0x08
OPT_AUTH_LENGTH    = 0x10

# RequestCommand
CMD_TCP = 0x01
CMD_UDP = 0x02
CMD_MUX = 0x03

GCM_NONCE_SIZE = 12
TAG = 16
MAX_CHUNK = 0x4000            # سقف payload هر chunk طبق spec
AUTH_ID_TIME_TOLERANCE = 120  # ثانیه — مثل Match در authid.go

RECV_BUF = 1024 * 1024


# ══════════════════════════════════════════════════════════════════════════════
# KDF — بازسازی دقیق KDF زنجیره‌ای فایل proxy/vmess/aead/kdf.go
# ══════════════════════════════════════════════════════════════════════════════
# نکته‌ی ظریف: در Go، hmac.New کارخانه‌ی hash را *دو بار* صدا می‌زند (یک بار برای
# outer و یک بار برای inner). در KDF زنجیره‌ای v2fly هر دو فراخوانی «همان» نمونه‌ی
# HMAC قبلی را برمی‌گردانند (بار اول داخل hash2 و بار دوم مستقیم) — یعنی inner و
# outer هر حلقه‌ی زنجیره هر دو به یک نمونه‌ی قبلی delegate می‌کنند و Sum/Reset ها
# به‌صورت stateful به هم گره می‌خورند. کلاس‌های پایین دقیقاً همین رفتار را بازسازی
# می‌کنند (مطابق crypto/internal/fips140/hmac/hmac.go).

class _GoSHA256:
    """معادل hash.Hash در Go برای sha256 (Sum بدون تغییر state)."""

    def __init__(self):
        self._h = hashlib.sha256()

    def write(self, p: bytes):
        self._h.update(p)

    def sum(self, b: bytes = b"") -> bytes:
        return b + self._h.copy().digest()

    def reset(self):
        self._h = hashlib.sha256()

    def marshal(self):
        return self._h.copy()

    def unmarshal(self, st):
        # نکته: حتماً کپی تازه — در گو هر UnmarshalBinary یک state نو می‌سازد؛
        # اگر state ذخیره‌شده با ارجاع برگرده، update بعدی آن را آلوده می‌کند.
        self._h = st.copy()


class _GoHMAC:
    """بازسازی دقیق HMAC گو با اجازه‌ی به‌اشتراک‌گذاری inner/outer (مسیر KDF)."""

    def __init__(self, factory: Callable[[], object], key: bytes):
        self.outer = factory()
        self.inner = factory()
        blocksize = 64
        k = key
        if len(k) > blocksize:
            self.outer.write(k)
            k = self.outer.sum()
        self.ipad = bytes(b ^ 0x36 for b in k.ljust(blocksize, b"\x00"))
        self.opad = bytes(b ^ 0x5C for b in k.ljust(blocksize, b"\x00"))
        self.inner.write(self.ipad)
        self._marshaled = False
        self._ipad_state = None
        self._opad_state = None

    def write(self, p: bytes):
        return self.inner.write(p)

    def sum(self, in_bytes: bytes = b"") -> bytes:
        orig_len = len(in_bytes)
        t = self.inner.sum(in_bytes)
        if self._marshaled:
            self.outer.unmarshal(self._opad_state)
        else:
            self.outer.reset()
            self.outer.write(self.opad)
        self.outer.write(t[orig_len:])
        return self.outer.sum(in_bytes[:orig_len])

    def reset(self):
        if self._marshaled:
            self.inner.unmarshal(self._ipad_state)
            return
        self.inner.reset()
        self.inner.write(self.ipad)
        try:
            self._ipad_state = self.inner.marshal()
            self.outer.reset()
            self.outer.write(self.opad)
            self._opad_state = self.outer.marshal()
            self._marshaled = True
        except Exception:
            self._marshaled = False


def _as_bytes(v) -> bytes:
    return v if isinstance(v, (bytes, bytearray)) else str(v).encode()


def kdf(key: bytes, *salts) -> bytes:
    """بازسازی یک‌به‌یک تابع KDF فایل proxy/vmess/aead/kdf.go.
    saltها مثل Go می‌توانند str یا bytes باشند."""
    h = _GoHMAC(_GoSHA256, KDF_SALT_VMESS_AEAD_KDF.encode())
    for v in salts:
        prev = h
        salt = _as_bytes(v)
        h = _GoHMAC(lambda: prev, salt)
    h.write(key)
    return h.sum()


def kdf16(key: bytes, *salts) -> bytes:
    return kdf(key, *salts)[:16]


# ── فرم بسته‌ی مستقل KDF تک‌salt — فقط برای تست صحت kdf() ─────────────────────
# اشتقاق دستی از زنجیره‌ی Go (H1(key=salt, inner=H0, outer=H0) که H0 = HMAC(K)).
# چون outerِ H1 همان H0 است، opad(salt) هم داخل همان استریم جذب می‌شود:
#   ۱) inner0 = sha256(ipadK ‖ ipad(salt) ‖ key)
#   ۲) d_b    = sha256(opadK ‖ inner0)                 ← H0.Sum اول
#   ۳) H0.Reset → inner0 = sha256(ipadK)               ← H1.outer.Reset()
#   ۴) H0.outer.Write(opad(salt)) → inner0 = sha256(ipadK ‖ opad(salt))
#   ۵) inner0.update(d_b)                              ← H1.outer.Write(digest)
#   ۶) نتیجه = sha256(opadK ‖ inner0)                  ← H0.Sum دوم
def closed_form_kdf1(key: bytes, salt) -> bytes:
    K = KDF_SALT_VMESS_AEAD_KDF.encode()
    ipad_k = bytes(b ^ 0x36 for b in K.ljust(64, b"\x00"))
    opad_k = bytes(b ^ 0x5C for b in K.ljust(64, b"\x00"))
    ipad_s = bytes(b ^ 0x36 for b in _as_bytes(salt).ljust(64, b"\x00"))
    opad_s = bytes(b ^ 0x5C for b in _as_bytes(salt).ljust(64, b"\x00"))

    s = hashlib.sha256(ipad_k + ipad_s + key)              # گام ۱
    d_b = hashlib.sha256(opad_k + s.digest()).digest()     # گام ۲
    s = hashlib.sha256(ipad_k + opad_s + d_b)              # گام ۳ تا ۵
    return hashlib.sha256(opad_k + s.digest()).digest()    # گام ۶


# ══════════════════════════════════════════════════════════════════════════════
# cmdKey و AuthID
# ══════════════════════════════════════════════════════════════════════════════

_cmd_key_cache: dict[str, bytes] = {}


def cmd_key_for(uuid_str: str) -> bytes:
    """cmdKey = MD5(uuid_bytes + CMD_KEY_TAIL) — مطابق protocol.NewID."""
    ck = _cmd_key_cache.get(uuid_str)
    if ck is None:
        raw = bytes.fromhex(uuid_str.replace("-", "").lower())
        ck = hashlib.md5(raw + CMD_KEY_TAIL).digest()
        _cmd_key_cache[uuid_str] = ck
    return ck


def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return dec.update(block) + dec.finalize()


def create_auth_id(cmd_key: bytes, t: int) -> bytes:
    """CreateAuthID از authid.go — pt = t(8BE) ‖ rand(4) ‖ crc32(4BE) → AES-ECB."""
    pt = struct.pack(">q", t) + secrets.token_bytes(4)
    pt += struct.pack(">I", zlib.crc32(pt) & 0xFFFFFFFF)
    return _aes_ecb_encrypt_block(kdf16(cmd_key, KDF_SALT_AUTH_ID_ENC_KEY), pt)


def decode_auth_id(cmd_key: bytes, auth_id: bytes) -> Optional[int]:
    """اگر authID برای این کلید معتبر باشد زمان داخلش را برمی‌گرداند وگرنه None.
    معادل AuthIDDecoder.Decode + چک crc32 (بدون چک replay/زمان)."""
    try:
        pt = _aes_ecb_decrypt_block(kdf16(cmd_key, KDF_SALT_AUTH_ID_ENC_KEY), auth_id)
    except Exception:
        return None
    if len(pt) != 16:
        return None
    if struct.unpack(">I", pt[12:16])[0] != (zlib.crc32(pt[:12]) & 0xFFFFFFFF):
        return None
    return struct.unpack(">q", pt[:8])[0]


class ReplayFilter:
    """معادل antireplay.NewMapFilter(120) — کش آخرین authIDهای دیده‌شده."""

    def __init__(self, size: int = 120):
        self.size = size
        self._seen: set = set()
        self._order: list = []

    def check_and_add(self, item) -> bool:
        """False یعنی replay."""
        if item in self._seen:
            return False
        self._seen.add(item)
        self._order.append(item)
        if len(self._order) > self.size:
            self._seen.discard(self._order.pop(0))
        return True


# ══════════════════════════════════════════════════════════════════════════════
# باز کردن هدر AEAD (مطابق OpenVMessAEADHeader)
# ══════════════════════════════════════════════════════════════════════════════

class VMessError(Exception):
    pass


class VMessAuthError(VMessError):
    pass


async def open_aead_header(cmd_key: bytes, auth_id: bytes,
                           read_exact: Callable[[int], Awaitable[bytes]]) -> bytes:
    """هدر رمز‌شده را می‌خواند و payload رمزگشایی‌شده را برمی‌گرداند.
    ساختار سیم: [18B طول+تگ] [8B nonce] [payload+16B تگ] — AAD = authID"""
    try:
        enc_len = await read_exact(18)
        nonce = await read_exact(8)
        len_key = kdf16(cmd_key, KDF_SALT_HDR_LEN_KEY, auth_id, nonce)
        len_iv = kdf(cmd_key, KDF_SALT_HDR_LEN_IV, auth_id, nonce)[:GCM_NONCE_SIZE]
        pt_len = struct.unpack(
            ">H", AESGCM(len_key).decrypt(len_iv, enc_len, auth_id)
        )[0]
        enc_payload = await read_exact(pt_len + TAG)
        payload_key = kdf16(cmd_key, KDF_SALT_HDR_PAYLOAD_KEY, auth_id, nonce)
        payload_iv = kdf(cmd_key, KDF_SALT_HDR_PAYLOAD_IV, auth_id, nonce)[:GCM_NONCE_SIZE]
        return AESGCM(payload_key).decrypt(payload_iv, enc_payload, auth_id)
    except VMessError:
        raise
    except Exception as exc:
        raise VMessAuthError(f"AEAD header open failed: {exc}") from exc


# ══════════════════════════════════════════════════════════════════════════════
# پارس هدر فرمان (مطابق DecodeRequestHeader بعد از AEAD)
# ══════════════════════════════════════════════════════════════════════════════

class VMessRequest:
    __slots__ = (
        "uuid", "version", "body_key", "body_iv", "response_token", "option",
        "padding_len", "security", "command", "address", "port",
    )

    def __init__(self):
        self.uuid = ""
        self.version = 0
        self.body_key = b""
        self.body_iv = b""
        self.response_token = 0
        self.option = 0
        self.padding_len = 0
        self.security = 0
        self.command = CMD_TCP
        self.address = ""
        self.port = 0


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def parse_command_header(payload: bytes) -> VMessRequest:
    """هدر رمزگشایی‌شده را پارس می‌کند — مطابق server.go:
    V ‖ bodyIV(16) ‖ bodyKey(16) ‖ respToken ‖ option ‖ padLen<<4|security ‖
    reserved ‖ command ‖ port(2BE) ‖ ATYP ‖ addr ‖ padding ‖ fnv1a(4)"""
    if len(payload) < 38:
        raise VMessError("command header too short")
    r = VMessRequest()
    r.version = payload[0]
    r.body_iv = payload[1:17]
    r.body_key = payload[17:33]
    r.response_token = payload[33]
    r.option = payload[34]
    r.padding_len = payload[35] >> 4
    r.security = payload[35] & 0x0F
    r.command = payload[37]

    pos = 38
    # PortThenAddress: اول پورت بعد ATYP/آدرس (مطابق addrParser در encoding.go)
    if len(payload) < pos + 2:
        raise VMessError("missing port")
    r.port = struct.unpack(">H", payload[pos:pos + 2])[0]
    pos += 2
    if len(payload) < pos + 1:
        raise VMessError("missing atyp")
    atyp = payload[pos]
    pos += 1
    if atyp == 0x01:
        if len(payload) < pos + 4:
            raise VMessError("short ipv4")
        r.address = ".".join(str(b) for b in payload[pos:pos + 4])
        pos += 4
    elif atyp == 0x02:
        if len(payload) < pos + 1:
            raise VMessError("short domain len")
        dlen = payload[pos]
        pos += 1
        if len(payload) < pos + dlen:
            raise VMessError("short domain")
        r.address = payload[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif atyp == 0x03:
        if len(payload) < pos + 16:
            raise VMessError("short ipv6")
        ab = payload[pos:pos + 16]
        r.address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
        pos += 16
    else:
        raise VMessError(f"unknown atyp {atyp}")
    pos += r.padding_len
    if len(payload) < pos + 4:
        raise VMessError("missing checksum")
    if _fnv1a32(payload[:pos]) != struct.unpack(">I", payload[pos:pos + 4])[0]:
        raise VMessError("invalid auth (fnv checksum mismatch)")
    return r


# ══════════════════════════════════════════════════════════════════════════════
# چانک‌های body — مطابق common/crypto/auth.go + ShakeSizeParser + GenerateChunkNonce
# ══════════════════════════════════════════════════════════════════════════════

class ShakeStream:
    """ShakeSizeParser — SHAKE-128(iv) پیوسته؛ هر next16 دو بایت مصرف می‌کند.
    ترتیب مصرف در هر chunk (هر دو سمت، مطابق گو): اول padding بعد mask."""

    def __init__(self, iv: bytes):
        self._shake = hashlib.shake_128(iv)
        self._consumed = 0

    def next16(self) -> int:
        out = self._shake.digest(self._consumed + 2)[self._consumed:self._consumed + 2]
        self._consumed += 2
        return int.from_bytes(out, "big")

    def next_padding_len(self) -> int:
        return self.next16() % 64

    def mask(self) -> int:
        return self.next16()


class _ChunkNonce:
    """GenerateChunkNonce از client.go — شمارنده‌ی uint16 BE داخل ۲ بایت اول IV."""

    def __init__(self, iv: bytes, size: int = GCM_NONCE_SIZE):
        self._c = bytearray(iv)
        self._count = 0
        self._size = size

    def next(self) -> bytes:
        self._c[0:2] = struct.pack(">H", self._count & 0xFFFF)
        self._count += 1
        return bytes(self._c[:self._size])


def make_body_aead(body_key: bytes, security: int):
    """AEAD امنیت انتخابی — AES-128-GCM یا ChaCha20-Poly1305."""
    if security == SEC_AES128_GCM:
        return AESGCM(body_key)
    if security == SEC_CHACHA20_POLY1305:
        # GenerateChacha20Poly1305Key از auth.go: MD5(key) ‖ MD5(MD5(key))
        first = hashlib.md5(body_key).digest()
        return ChaCha20Poly1305(first + hashlib.md5(first).digest())
    raise VMessError(f"unsupported security {security}")


class BodyReader:
    """خواننده‌ی استریمی چانک‌های body (درخواست کلاینت → سرور).
    مطابق AuthenticationReader: chunk = [size(2B masked)] [AEAD(payload)] [padding]
    EOF وقتی size == overhead + padding (چانک خالی)."""

    def __init__(self, body_key: bytes, body_iv: bytes, security: int,
                 option: int, fill: Callable[[int], Awaitable[bytes]]):
        self._aead = make_body_aead(body_key, security)
        self._authlen = bool(option & OPT_AUTH_LENGTH)
        # نکته‌ی گو: با AuthenticatedLength شمارنده‌ی سایز کاملاً جایگزین می‌شود —
        # یعنی Shake masking و padding هر دو حذف می‌شوند (سایز خودش AEAD است).
        self._masking = bool(option & OPT_CHUNK_MASKING) and not self._authlen
        self._padding = bool(option & OPT_GLOBAL_PADDING) and not self._authlen
        if self._authlen:
            self._len_aead = make_body_aead(kdf16(body_key, "auth_len"), security)
            self._len_nonce = _ChunkNonce(body_iv)
        else:
            self._len_aead = None
        self._shake = ShakeStream(body_iv) if self._masking else None
        self._payload_nonce = _ChunkNonce(body_iv)
        self._fill = fill
        self._buf = bytearray()
        self._done = False

    async def _need(self, n: int) -> bool:
        """True یعنی n بایت آماده است؛ False یعنی EOF تمیز در مرز chunk."""
        while len(self._buf) < n:
            chunk = await self._fill(RECV_BUF)
            if not chunk:
                return False
            self._buf += chunk
        return True

    async def read(self) -> bytes:
        """یک تکه‌ی payload رمزگشایی‌شده برمی‌گرداند؛ b"" یعنی EOF."""
        if self._done:
            return b""

        if self._authlen:
            if not await self._need(2 + TAG):
                self._done = True
                return b""
            enc_size = bytes(self._buf[:2 + TAG])
            del self._buf[:2 + TAG]
            size = struct.unpack(
                ">H", self._len_aead.decrypt(self._len_nonce.next(), enc_size, None)
            )[0] + TAG
            if size == TAG:
                self._done = True
                return b""
            if size < TAG or size > MAX_CHUNK + TAG:
                raise VMessError(f"invalid chunk size {size}")
            if not await self._need(size):
                raise VMessError("truncated chunk payload")
            enc_payload = bytes(self._buf[:size])
            del self._buf[:size]
            return self._aead.decrypt(self._payload_nonce.next(), enc_payload, None)

        if not await self._need(2):
            self._done = True
            return b""

        # ترتیب مصرف shake مطابق readSize در گو: اول padding بعد mask
        pad_len = (self._shake.next_padding_len() if self._shake else 0) \
            if self._padding else 0
        raw_size = int.from_bytes(bytes(self._buf[:2]), "big")
        del self._buf[:2]
        size = raw_size ^ (self._shake.mask() if self._shake else 0)

        if size == TAG + pad_len:
            self._done = True
            return b""
        if size < TAG + pad_len or size > MAX_CHUNK + TAG + 64:
            raise VMessError(f"invalid chunk size {size}")

        if not await self._need(size):
            raise VMessError("truncated chunk payload")
        enc_payload = bytes(self._buf[:size - pad_len])
        del self._buf[:size]
        return self._aead.decrypt(self._payload_nonce.next(), enc_payload, None)


class BodyWriter:
    """نویسنده‌ی چانک‌های body (پاسخ سرور → کلاینت). خروجی bytes."""

    def __init__(self, body_key: bytes, body_iv: bytes, security: int, option: int):
        self._aead = make_body_aead(body_key, security)
        self._masking = bool(option & OPT_CHUNK_MASKING)
        self._padding = bool(option & OPT_GLOBAL_PADDING) and not bool(option & OPT_AUTH_LENGTH)
        self._authlen = bool(option & OPT_AUTH_LENGTH)
        if self._authlen:
            self._len_aead = make_body_aead(kdf16(body_key, "auth_len"), security)
            self._len_nonce = _ChunkNonce(body_iv)
        else:
            self._len_aead = None
        self._shake = ShakeStream(body_iv) if self._masking else None
        self._payload_nonce = _ChunkNonce(body_iv)

    def _seal(self, payload: bytes) -> bytes:
        padding_size = self._shake.next_padding_len() if self._padding else 0
        encrypted_size = len(payload) + TAG
        out = bytearray()
        if self._authlen:
            # AEADChunkSizeParser.Encode: uint16(سایز بدون تگ) رمز می‌شود
            out += self._len_aead.encrypt(
                self._len_nonce.next(), struct.pack(">H", len(payload)), None
            )
        else:
            size_val = encrypted_size + padding_size
            if self._shake:
                out += struct.pack(">H", size_val ^ self._shake.mask())
            else:
                out += struct.pack(">H", size_val)
        out += self._aead.encrypt(self._payload_nonce.next(), payload, None)
        if padding_size:
            out += secrets.token_bytes(padding_size)
        return bytes(out)

    def write_chunk(self, payload: bytes) -> bytes:
        if len(payload) <= MAX_CHUNK:
            return self._seal(payload)
        # شکستن payload بزرگ به چند chunk (مطابق writeStream در گو)
        return b"".join(
            self._seal(payload[i:i + MAX_CHUNK]) for i in range(0, len(payload), MAX_CHUNK)
        )

    def write_eof(self) -> bytes:
        """چانک خالی پایانی — سیگنال EOF برای کلاینت (ChunkStream)."""
        return self._seal(b"")


# ══════════════════════════════════════════════════════════════════════════════
# هدر پاسخ — مطابق EncodeResponseHeader (مسیر AEAD)
# ══════════════════════════════════════════════════════════════════════════════

def _response_keys(request: VMessRequest) -> tuple[bytes, bytes]:
    return (hashlib.sha256(request.body_key).digest()[:16],
            hashlib.sha256(request.body_iv).digest()[:16])


def response_header_bytes(request: VMessRequest) -> bytes:
    """دو بلوک AEAD هدر پاسخ: [18B طول] [payload=4B+16B تگ]
    plaintext هدر: [responseToken, option=0, cmdID=0, cmdLen=0]
    مطابق EncodeResponseHeader در گو:
      lenKey = KDF16(respKey, "…Len Key") · lenIV = KDF(respIV, "…Len IV")[:12]
      payKey = KDF16(respKey, "…Key")     · payIV = KDF(respIV, "…IV")[:12]"""
    resp_key, resp_iv = _response_keys(request)
    pt = bytes([request.response_token, 0x00, 0x00, 0x00])
    enc_len = AESGCM(kdf16(resp_key, KDF_SALT_RESP_HDR_LEN_KEY)).encrypt(
        kdf(resp_iv, KDF_SALT_RESP_HDR_LEN_IV)[:GCM_NONCE_SIZE],
        struct.pack(">H", len(pt)), None,
    )
    enc_payload = AESGCM(kdf16(resp_key, KDF_SALT_RESP_HDR_PAYLOAD_KEY)).encrypt(
        kdf(resp_iv, KDF_SALT_RESP_HDR_PAYLOAD_IV)[:GCM_NONCE_SIZE],
        pt, None,
    )
    return enc_len + enc_payload


def response_body_writer(request: VMessRequest) -> BodyWriter:
    resp_key, resp_iv = _response_keys(request)
    return BodyWriter(resp_key, resp_iv, request.security, request.option)


# ══════════════════════════════════════════════════════════════════════════════
# سشن سرور — اعتبارسنجی کاربر و جریان کامل درخواست
# ══════════════════════════════════════════════════════════════════════════════

class _AuthIDValidator:
    """معادل AuthIDDecoderHolder.Match — جست‌وجو بین کاربران فعال + ضد replay."""

    def __init__(self):
        self._keys: dict[bytes, str] = {}
        self._replay = ReplayFilter(120)

    def add_user(self, uuid_str: str):
        self._keys[cmd_key_for(uuid_str)] = uuid_str

    def remove_user(self, uuid_str: str):
        self._keys.pop(cmd_key_for(uuid_str), None)

    def match(self, auth_id: bytes) -> Optional[str]:
        for ck, uuid_str in self._keys.items():
            t = decode_auth_id(ck, auth_id)
            if t is None:
                continue
            if t < 0 or abs(t - int(time.time())) > AUTH_ID_TIME_TOLERANCE:
                continue
            if not self._replay.check_and_add(bytes(auth_id)):
                raise VMessAuthError("replayed request")
            return uuid_str
        return None


_validator = _AuthIDValidator()


def register_user(uuid_str: str):
    _validator.add_user(uuid_str)


def unregister_user(uuid_str: str):
    _validator.remove_user(uuid_str)


async def decode_request(
    read_exact: Callable[[int], Awaitable[bytes]],
    fill: Optional[Callable[[int], Awaitable[bytes]]] = None,
    expected_uuid: Optional[str] = None,
) -> tuple[VMessRequest, BodyReader]:
    """کل هدر درخواست را می‌خواند و (request, body_reader) برمی‌گرداند.
    read_exact دقیقاً n بایت می‌خواند (هدر)؛ fill هرچه آماده باشد می‌دهد (body).
    اگر fill داده نشود همان read_exact استفاده می‌شود.
    اگر expected_uuid داده شود فقط همان کاربر پذیرفته می‌شود؛ وگرنه بین همه‌ی
    کاربران ثبت‌شده جست‌وجو می‌شود (مثل سرور واقعی v2ray)."""
    auth_id = await read_exact(16)
    if expected_uuid:
        if decode_auth_id(cmd_key_for(expected_uuid), auth_id) is None:
            raise VMessAuthError("unknown user or expired auth id")
        uuid_used = expected_uuid
    else:
        uuid_used = _validator.match(auth_id)
        if uuid_used is None:
            raise VMessAuthError("unknown user")

    payload = await open_aead_header(cmd_key_for(uuid_used), auth_id, read_exact)
    r = parse_command_header(payload)
    r.uuid = uuid_used

    if r.command != CMD_TCP:
        raise VMessError("only TCP command is supported")
    if r.security not in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
        raise VMessError(f"unsupported security {r.security}")
    if (r.option & OPT_GLOBAL_PADDING) and (r.option & OPT_AUTH_LENGTH):
        raise VMessError("invalid option: GlobalPadding + AuthenticatedLength")

    reader = BodyReader(r.body_key, r.body_iv, r.security, r.option, fill or read_exact)
    return r, reader
