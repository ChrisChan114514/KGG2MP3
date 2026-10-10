#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Batch-decrypt KuGou KGG/KGM-v5 files and produce MP3 files.

The KGG v5 container needs the per-track ekey stored in KuGou's local
KGMusicV3.db.  This program decrypts that database in memory, decrypts each
audio stream in chunks, and either copies an already-MP3 stream or pipes other
audio formats to FFmpeg.

The container/database/QMC2 compatibility work references Kugo Music
Converter (GPL-3.0), whose upstream algorithm sources include Unlock Music
CLI (MIT). See THIRD_PARTY_NOTICES.md in the repository root.

Use this only for files you downloaded legitimately and are entitled to use.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import itertools
import math
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    from Crypto.Cipher import AES as _CryptoAES
    from Crypto.Util.strxor import strxor as _crypto_strxor
except ModuleNotFoundError:  # Windows CNG and a small XOR fallback are used instead.
    _CryptoAES = None
    _crypto_strxor = None


KGM_MAGIC = bytes.fromhex("7cd532eb86027f4ba8afa68e0fff9914")
VPR_MAGIC = bytes.fromhex("0528bc96e9e45a4391aabdd07af53631")
SQLITE_HEADER = b"SQLite format 3\x00"
DB_PAGE_SIZE = 0x400
DEFAULT_DB_MASTER_KEY = bytes.fromhex("1d613145b247bf7f3d189672144fe4bf")
RAW_KEY_PREFIX_V2 = b"QQMusic EncV2,Key:"
DERIVE_V2_KEY_1 = bytes.fromhex("3338365a4a592140232a24255e262928")
DERIVE_V2_KEY_2 = bytes.fromhex("2a2a232128232425265e6131635a2c54")
DEFAULT_CHUNK_SIZE = 1024 * 1024


class KGGError(RuntimeError):
    """A readable conversion error."""


class _WindowsAESCBC:
    """Minimal no-padding AES-CBC wrapper around Windows CNG (bcrypt.dll)."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise KGGError("未安装 pycryptodome，且当前系统不是 Windows，无法执行 AES")
        from ctypes import wintypes

        self._wintypes = wintypes
        self._bcrypt = ctypes.WinDLL("bcrypt.dll")
        self._provider = ctypes.c_void_p()

        self._bcrypt.BCryptOpenAlgorithmProvider.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            wintypes.ULONG,
        ]
        self._bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
        self._bcrypt.BCryptSetProperty.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        self._bcrypt.BCryptSetProperty.restype = ctypes.c_long
        self._bcrypt.BCryptGetProperty.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.ULONG,
        ]
        self._bcrypt.BCryptGetProperty.restype = ctypes.c_long
        self._bcrypt.BCryptGenerateSymmetricKey.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        self._bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
        self._bcrypt.BCryptDecrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.ULONG,
        ]
        self._bcrypt.BCryptDecrypt.restype = ctypes.c_long
        self._bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
        self._bcrypt.BCryptDestroyKey.restype = ctypes.c_long
        self._bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.ULONG]
        self._bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long

        self._check(
            self._bcrypt.BCryptOpenAlgorithmProvider(
                ctypes.byref(self._provider), "AES", None, 0
            ),
            "BCryptOpenAlgorithmProvider",
        )
        chaining_mode = ctypes.create_unicode_buffer("ChainingModeCBC")
        self._check(
            self._bcrypt.BCryptSetProperty(
                self._provider,
                "ChainingMode",
                ctypes.cast(chaining_mode, ctypes.c_void_p),
                ctypes.sizeof(chaining_mode),
                0,
            ),
            "BCryptSetProperty(ChainingModeCBC)",
        )
        object_length = wintypes.ULONG()
        copied = wintypes.ULONG()
        self._check(
            self._bcrypt.BCryptGetProperty(
                self._provider,
                "ObjectLength",
                ctypes.byref(object_length),
                ctypes.sizeof(object_length),
                ctypes.byref(copied),
                0,
            ),
            "BCryptGetProperty(ObjectLength)",
        )
        self._object_length = object_length.value

    @staticmethod
    def _check(status: int, operation: str) -> None:
        if status != 0:
            raise KGGError(f"Windows AES 调用失败：{operation}，NTSTATUS=0x{status & 0xFFFFFFFF:08X}")

    def decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        if len(ciphertext) % 16 or len(key) not in {16, 24, 32} or len(iv) != 16:
            raise KGGError("AES-CBC 输入长度无效")
        key_handle = ctypes.c_void_p()
        key_object = (ctypes.c_ubyte * self._object_length)()
        key_buffer = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        self._check(
            self._bcrypt.BCryptGenerateSymmetricKey(
                self._provider,
                ctypes.byref(key_handle),
                key_object,
                self._object_length,
                key_buffer,
                len(key),
                0,
            ),
            "BCryptGenerateSymmetricKey",
        )
        try:
            input_buffer = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
            iv_buffer = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
            output_buffer = (ctypes.c_ubyte * len(ciphertext))()
            written = self._wintypes.ULONG()
            self._check(
                self._bcrypt.BCryptDecrypt(
                    key_handle,
                    input_buffer,
                    len(ciphertext),
                    None,
                    iv_buffer,
                    len(iv),
                    output_buffer,
                    len(ciphertext),
                    ctypes.byref(written),
                    0,
                ),
                "BCryptDecrypt",
            )
            if written.value != len(ciphertext):
                raise KGGError(
                    f"Windows AES 输出长度异常：{written.value}/{len(ciphertext)}"
                )
            return bytes(output_buffer)
        finally:
            self._bcrypt.BCryptDestroyKey(key_handle)

    def close(self) -> None:
        if self._provider:
            self._bcrypt.BCryptCloseAlgorithmProvider(self._provider, 0)
            self._provider = ctypes.c_void_p()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


_windows_aes: _WindowsAESCBC | None = None


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    global _windows_aes
    if _CryptoAES is not None:
        return _CryptoAES.new(key, _CryptoAES.MODE_CBC, iv).decrypt(ciphertext)
    if _windows_aes is None:
        _windows_aes = _WindowsAESCBC()
    return _windows_aes.decrypt(ciphertext, key, iv)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise KGGError("内部 XOR 缓冲区长度不一致")
    if _crypto_strxor is not None:
        return _crypto_strxor(left, right)
    return bytes(a ^ b for a, b in zip(left, right))


@dataclass(frozen=True)
class KGGHeader:
    audio_offset: int
    crypto_version: int
    audio_hash: str
    payload_size: int


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _next_page_iv(seed: int) -> int:
    left = _u32(seed * 0x9EF4)
    right = _u32((seed // 0xCE26) * 0x7FFFFF07)
    value = _u32(left - right)
    if value & 0x80000000 == 0:
        return value
    return _u32(value + 0x7FFFFF07)


def _derive_page_aes_key(page_number: int, master_key: bytes) -> bytes:
    material = master_key + struct.pack("<II", page_number, 0x546C4173)
    return hashlib.md5(material).digest()


def _derive_page_aes_iv(page_number: int) -> bytes:
    seed = _u32(page_number + 1)
    values: list[int] = []
    for _ in range(4):
        seed = _next_page_iv(seed)
        values.append(seed)
    return hashlib.md5(struct.pack("<IIII", *values)).digest()


def _decrypt_db_page(page: bytes, page_number: int, master_key: bytes) -> bytes:
    key = _derive_page_aes_key(page_number, master_key)
    iv = _derive_page_aes_iv(page_number)
    return _aes_cbc_decrypt(page, key, iv)


def _validate_encrypted_page_one(page: bytes) -> None:
    if len(page) < 0x18:
        raise KGGError("KGMusicV3.db 首页过短")
    value_10, value_14 = struct.unpack_from("<II", page, 0x10)
    page_size = ((value_10 & 0xFF) << 8) | ((value_10 & 0xFF00) << 16)
    is_power_of_two = page_size > 0 and (page_size & (page_size - 1)) == 0
    if value_14 != 0x20204000 or not 0x200 <= page_size <= 0x10000 or not is_power_of_two:
        raise KGGError("KGMusicV3.db 首页结构不符合预期")


def _decrypt_page_one(page: bytes, master_key: bytes) -> bytes:
    work = bytearray(page)
    _validate_encrypted_page_one(work)
    expected = bytes(work[0x10:0x18])
    work[0x10:0x18] = work[0x08:0x10]
    work[0x10:] = _decrypt_db_page(bytes(work[0x10:]), 1, master_key)
    if work[0x10:0x18] != expected:
        raise KGGError("KGMusicV3.db 首页完整性校验失败（主密钥或数据库版本不匹配）")
    work[: len(SQLITE_HEADER)] = SQLITE_HEADER
    return bytes(work)


def _master_key_candidates() -> list[bytes]:
    candidates: list[bytes] = []
    custom = os.environ.get("KGG_DB_MASTER_KEY", "").strip()
    if custom:
        try:
            raw = bytes.fromhex(custom)
        except ValueError as exc:
            raise KGGError("环境变量 KGG_DB_MASTER_KEY 必须是 32 位十六进制字符串") from exc
        if len(raw) != 16:
            raise KGGError("环境变量 KGG_DB_MASTER_KEY 解码后必须是 16 字节")
        candidates.append(raw)
    if DEFAULT_DB_MASTER_KEY not in candidates:
        candidates.append(DEFAULT_DB_MASTER_KEY)
    return candidates


def decrypt_kgmusic_database(encrypted: bytes) -> bytes:
    """Return a plaintext SQLite database without writing it to disk."""
    if encrypted.startswith(SQLITE_HEADER):
        return encrypted
    if not encrypted or len(encrypted) % DB_PAGE_SIZE:
        raise KGGError(f"KGMusicV3.db 大小无效：{len(encrypted)} 字节")

    chosen_key: bytes | None = None
    first_page: bytes | None = None
    last_error: Exception | None = None
    for candidate in _master_key_candidates():
        try:
            first_page = _decrypt_page_one(encrypted[:DB_PAGE_SIZE], candidate)
        except Exception as exc:  # Try a possible rotated master key next.
            last_error = exc
            continue
        chosen_key = candidate
        break
    if chosen_key is None or first_page is None:
        raise KGGError(f"无法解密 KGMusicV3.db：首页校验失败；{last_error}")

    plaintext = bytearray(len(encrypted))
    plaintext[:DB_PAGE_SIZE] = first_page
    for start in range(DB_PAGE_SIZE, len(encrypted), DB_PAGE_SIZE):
        page_number = start // DB_PAGE_SIZE + 1
        plaintext[start : start + DB_PAGE_SIZE] = _decrypt_db_page(
            encrypted[start : start + DB_PAGE_SIZE], page_number, chosen_key
        )
    return bytes(plaintext)


def load_key_map(db_path: Path) -> dict[str, str]:
    try:
        encrypted = db_path.read_bytes()
    except PermissionError as exc:
        raise KGGError(
            f"无法读取数据库（很可能正被酷狗独占）：{db_path}\n"
            "请完全退出酷狗客户端（包括系统托盘图标）后重试。"
        ) from exc
    except OSError as exc:
        if getattr(exc, "winerror", None) in {32, 33}:
            raise KGGError(
                f"无法读取数据库（很可能正被酷狗独占）：{db_path}\n"
                "请完全退出酷狗客户端（包括系统托盘图标）后重试。"
            ) from exc
        raise KGGError(f"读取数据库失败：{db_path}；{exc}") from exc

    plaintext = decrypt_kgmusic_database(encrypted)
    if not hasattr(sqlite3.Connection, "deserialize"):
        raise KGGError("当前 Python 的 sqlite3 不支持 deserialize，请使用较新的 Conda Python")

    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(plaintext)
        rows = connection.execute(
            "SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems "
            "WHERE EncryptionKeyId IS NOT NULL AND EncryptionKeyId != '' "
            "AND EncryptionKey IS NOT NULL AND EncryptionKey != ''"
        )
        result: dict[str, str] = {}
        for key_id, ekey in rows:
            if isinstance(key_id, bytes):
                key_id = key_id.decode("utf-8", errors="strict")
            if isinstance(ekey, bytes):
                ekey = ekey.decode("utf-8", errors="strict")
            result[str(key_id)] = str(ekey)
        return result
    except sqlite3.DatabaseError as exc:
        raise KGGError(f"解密后的 KGMusicV3.db 无法查询：{exc}") from exc
    finally:
        connection.close()


def read_kgg_header(path: Path) -> KGGHeader:
    try:
        file_size = path.stat().st_size
        with path.open("rb") as source:
            fixed = source.read(0x44)
            if len(fixed) != 0x44:
                raise KGGError("文件头不足 68 字节")
            if fixed[:16] not in {KGM_MAGIC, VPR_MAGIC}:
                raise KGGError("不是受支持的 KGG/KGM v5 容器")
            audio_offset, crypto_version = struct.unpack_from("<II", fixed, 0x10)
            raw_hash_length = source.read(4)
            if len(raw_hash_length) != 4:
                raise KGGError("文件头缺少音频哈希长度")
            hash_length = struct.unpack("<I", raw_hash_length)[0]
            if not 1 <= hash_length <= 256:
                raise KGGError(f"音频哈希长度异常：{hash_length}")
            raw_hash = source.read(hash_length)
            if len(raw_hash) != hash_length:
                raise KGGError("文件头中的音频哈希不完整")
    except OSError as exc:
        raise KGGError(f"读取文件失败：{exc}") from exc

    if crypto_version != 5:
        raise KGGError(f"仅支持 crypto version 5，当前为 {crypto_version}")
    if audio_offset < 0x48 + hash_length or audio_offset >= file_size:
        raise KGGError(f"音频数据偏移异常：0x{audio_offset:X}")
    try:
        audio_hash = raw_hash.decode("ascii")
    except UnicodeDecodeError as exc:
        raise KGGError("音频哈希不是 ASCII 文本") from exc
    return KGGHeader(audio_offset, crypto_version, audio_hash, file_size - audio_offset)


def _tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 8 or len(key) != 16:
        raise KGGError("TEA 块或密钥长度无效")
    value_0, value_1 = struct.unpack(">II", block)
    key_0, key_1, key_2, key_3 = struct.unpack(">IIII", key)
    delta = 0x9E3779B9
    # Unlock Music uses x/crypto/tea.NewCipherWithRounds(key, 32). In that
    # API one loop below accounts for two Feistel rounds, so 32 rounds means
    # 16 loops (the package's standard 64-round TEA uses 32 loops).
    cycles = 16
    total = _u32(delta * cycles)
    for _ in range(cycles):
        value_1 = _u32(
            value_1
            - (
                _u32((value_0 << 4) + key_2)
                ^ _u32(value_0 + total)
                ^ _u32((value_0 >> 5) + key_3)
            )
        )
        value_0 = _u32(
            value_0
            - (
                _u32((value_1 << 4) + key_0)
                ^ _u32(value_1 + total)
                ^ _u32((value_1 >> 5) + key_1)
            )
        )
        total = _u32(total - delta)
    return struct.pack(">II", value_0, value_1)


def _decrypt_tencent_tea(ciphertext: bytes, key: bytes) -> bytes:
    salt_length = 2
    zero_length = 7
    if len(ciphertext) % 8:
        raise KGGError("eKey 的 TEA 密文没有按 8 字节对齐")
    if len(ciphertext) < 16:
        raise KGGError("eKey 的 TEA 密文过短")

    destination = bytearray(_tea_decrypt_block(ciphertext[:8], key))
    pad_length = destination[0] & 0x07
    output_length = len(ciphertext) - 1 - pad_length - salt_length - zero_length
    if output_length < 0:
        raise KGGError("eKey 的 TEA 填充长度无效")

    previous_iv = bytes(8)
    current_iv = ciphertext[:8]
    input_position = 8
    destination_index = 1 + pad_length

    def decrypt_next_block() -> None:
        nonlocal previous_iv, current_iv, input_position, destination_index, destination
        if input_position + 8 > len(ciphertext):
            raise KGGError("eKey 的 TEA 密文意外结束")
        previous_iv = current_iv
        current_iv = ciphertext[input_position : input_position + 8]
        mixed = bytes(a ^ b for a, b in zip(destination, current_iv))
        destination = bytearray(_tea_decrypt_block(mixed, key))
        input_position += 8
        destination_index = 0

    salt_read = 0
    while salt_read < salt_length:
        if destination_index < 8:
            destination_index += 1
            salt_read += 1
        else:
            decrypt_next_block()

    output = bytearray(output_length)
    output_position = 0
    while output_position < output_length:
        if destination_index < 8:
            output[output_position] = destination[destination_index] ^ previous_iv[destination_index]
            destination_index += 1
            output_position += 1
        else:
            decrypt_next_block()

    # Match the reference decoder's padding check. Valid ekeys end with seven zero bytes.
    if destination_index >= 8 or destination[destination_index] != previous_iv[destination_index]:
        raise KGGError("eKey 的 TEA 尾部校验失败")
    return bytes(output)


def _simple_make_key(salt: int, length: int) -> bytes:
    return bytes(int(abs(math.tan(salt + index * 0.1)) * 100.0) & 0xFF for index in range(length))


def derive_qmc2_key(ekey: str) -> bytes:
    try:
        raw = base64.b64decode(ekey, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise KGGError("数据库中的 eKey 不是有效 Base64") from exc

    if raw.startswith(RAW_KEY_PREFIX_V2):
        nested = raw[len(RAW_KEY_PREFIX_V2) :]
        nested = _decrypt_tencent_tea(nested, DERIVE_V2_KEY_1)
        nested = _decrypt_tencent_tea(nested, DERIVE_V2_KEY_2)
        try:
            raw = base64.b64decode(nested, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise KGGError("eKey V2 内层不是有效 Base64") from exc

    if len(raw) < 16:
        raise KGGError("eKey 解码后的长度过短")
    simple_key = _simple_make_key(106, 8)
    tea_key = bytearray(16)
    for index in range(8):
        tea_key[index * 2] = simple_key[index]
        tea_key[index * 2 + 1] = raw[index]
    return raw[:8] + _decrypt_tencent_tea(raw[8:], bytes(tea_key))


class QMC2MapCipher:
    PERIOD = 0x7FFF

    def __init__(self, key: bytes) -> None:
        if not key:
            raise KGGError("QMC2 MAP 密钥为空")
        self._key = key
        masks = bytearray(0x8000)
        for offset in range(len(masks)):
            masks[offset] = self._mask(offset)
        self._masks = bytes(masks)
        self._cycle = self._masks[: self.PERIOD]

    def _mask(self, offset: int) -> int:
        if offset > self.PERIOD:
            offset %= self.PERIOD
        index = (offset * offset + 71214) % len(self._key)
        value = self._key[index]
        shift = ((index & 0x07) + 4) % 8
        return ((value << shift) | (value >> shift)) & 0xFF

    def _keystream(self, offset: int, length: int) -> bytes:
        parts: list[bytes] = []
        remaining = length
        if offset <= self.PERIOD and remaining:
            take = min(remaining, self.PERIOD - offset + 1)
            parts.append(self._masks[offset : offset + take])
            offset += take
            remaining -= take
        if remaining:
            position = offset % self.PERIOD
            if position:
                take = min(remaining, self.PERIOD - position)
                parts.append(self._cycle[position : position + take])
                offset += take
                remaining -= take
            if remaining >= self.PERIOD:
                repeats, remaining = divmod(remaining, self.PERIOD)
                parts.append(self._cycle * repeats)
            if remaining:
                parts.append(self._cycle[:remaining])
        return b"".join(parts)

    def decrypt(self, data: bytes, offset: int) -> bytes:
        return _xor_bytes(data, self._keystream(offset, len(data)))


class QMC2RC4Cipher:
    SEGMENT_SIZE = 5120
    FIRST_SEGMENT_SIZE = 128

    def __init__(self, key: bytes) -> None:
        if not key:
            raise KGGError("QMC2 RC4 密钥为空")
        self._key = key
        self._size = len(key)
        box = bytearray((index & 0xFF) for index in range(self._size))
        swap_index = 0
        for index in range(self._size):
            swap_index = (swap_index + box[index] + key[index % self._size]) % self._size
            box[index], box[swap_index] = box[swap_index], box[index]
        self._box = bytes(box)

        hash_value = 1
        for value in key:
            if value == 0:
                continue
            next_hash = _u32(hash_value * value)
            if next_hash == 0 or next_hash <= hash_value:
                break
            hash_value = next_hash
        self._hash = hash_value

    def _segment_skip(self, segment_id: int) -> int:
        seed = self._key[segment_id % self._size]
        if seed == 0:
            raise KGGError("QMC2 RC4 密钥包含无效的零 seed")
        index = int(float(self._hash) / float((segment_id + 1) * seed) * 100.0)
        return index % self._size

    def _decrypt_segment(self, buffer: bytearray, start: int, length: int, offset: int) -> None:
        box = bytearray(self._box)
        index_j = 0
        index_k = 0
        skip_length = offset % self.SEGMENT_SIZE + self._segment_skip(offset // self.SEGMENT_SIZE)
        for _ in range(skip_length):
            index_j = (index_j + 1) % self._size
            index_k = (box[index_j] + index_k) % self._size
            box[index_j], box[index_k] = box[index_k], box[index_j]
        end = start + length
        for position in range(start, end):
            index_j = (index_j + 1) % self._size
            index_k = (box[index_j] + index_k) % self._size
            box[index_j], box[index_k] = box[index_k], box[index_j]
            buffer[position] ^= box[(box[index_j] + box[index_k]) % self._size]

    def decrypt(self, data: bytes, offset: int) -> bytes:
        buffer = bytearray(data)
        remaining = len(buffer)
        processed = 0
        current_offset = offset

        if current_offset < self.FIRST_SEGMENT_SIZE:
            block_size = min(remaining, self.FIRST_SEGMENT_SIZE - current_offset)
            for index in range(block_size):
                buffer[index] ^= self._key[self._segment_skip(current_offset + index)]
            current_offset += block_size
            processed += block_size
            remaining -= block_size
            if not remaining:
                return bytes(buffer)

        remainder = current_offset % self.SEGMENT_SIZE
        if remainder:
            block_size = min(remaining, self.SEGMENT_SIZE - remainder)
            self._decrypt_segment(buffer, processed, block_size, current_offset)
            current_offset += block_size
            processed += block_size
            remaining -= block_size
            if not remaining:
                return bytes(buffer)

        while remaining > self.SEGMENT_SIZE:
            self._decrypt_segment(buffer, processed, self.SEGMENT_SIZE, current_offset)
            current_offset += self.SEGMENT_SIZE
            processed += self.SEGMENT_SIZE
            remaining -= self.SEGMENT_SIZE
        if remaining:
            self._decrypt_segment(buffer, processed, remaining, current_offset)
        return bytes(buffer)


def create_qmc2_cipher(ekey: str) -> QMC2MapCipher | QMC2RC4Cipher:
    key = derive_qmc2_key(ekey)
    if len(key) > 300:
        return QMC2RC4Cipher(key)
    return QMC2MapCipher(key)


def iter_decrypted_audio(
    path: Path,
    header: KGGHeader,
    cipher: QMC2MapCipher | QMC2RC4Cipher,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[bytes]:
    offset = 0
    with path.open("rb") as source:
        source.seek(header.audio_offset)
        while True:
            encrypted = source.read(chunk_size)
            if not encrypted:
                break
            yield cipher.decrypt(encrypted, offset)
            offset += len(encrypted)


def _is_mp3(data: bytes) -> bool:
    if data.startswith(b"ID3"):
        return True
    if len(data) < 4 or data[0] != 0xFF or data[1] & 0xE0 != 0xE0:
        return False
    layer = (data[1] >> 1) & 0x03
    bitrate_index = (data[2] >> 4) & 0x0F
    sample_rate_index = (data[2] >> 2) & 0x03
    return layer != 0 and bitrate_index not in {0, 15} and sample_rate_index != 3


def _describe_audio(data: bytes) -> str:
    if _is_mp3(data):
        return "MP3"
    if data.startswith(b"fLaC"):
        return "FLAC"
    if data.startswith(b"OggS"):
        return "OGG"
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "WAV"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "MP4/M4A"
    if data.startswith(bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c")):
        return "WMA/ASF"
    if len(data) >= 2 and data[0] == 0xFF and data[1] & 0xF6 == 0xF0:
        return "AAC"
    return "未知音频"


def _temporary_output(output_path: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{output_path.stem}.", suffix=".part.mp3", dir=output_path.parent
    )
    os.close(descriptor)
    return Path(name)


def _verify_mp3(path: Path, ffprobe: str | None) -> None:
    if ffprobe is None:
        return
    completed = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-select_streams",
            "a:0",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    codec = completed.stdout.strip().lower()
    if completed.returncode != 0 or codec != "mp3":
        detail = completed.stderr.strip() or f"检测到 codec={codec or '空'}"
        raise KGGError(f"输出 MP3 校验失败：{detail}")


def _write_decrypted_mp3(chunks: Iterable[bytes], temporary_path: Path) -> None:
    with temporary_path.open("wb") as target:
        for chunk in chunks:
            target.write(chunk)


def _transcode_to_mp3(
    chunks: Iterable[bytes], temporary_path: Path, ffmpeg: str, bitrate: str
) -> None:
    command = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        "pipe:0",
        "-map",
        "0:a:0",
        "-map_metadata",
        "0",
        "-c:a",
        "libmp3lame",
        "-b:a",
        bitrate,
        "-id3v2_version",
        "3",
        "-f",
        "mp3",
        str(temporary_path),
    ]
    with tempfile.TemporaryFile() as error_log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=error_log,
        )
        broken_pipe = False
        assert process.stdin is not None
        try:
            for chunk in chunks:
                process.stdin.write(chunk)
        except BrokenPipeError:
            broken_pipe = True
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                broken_pipe = True
        return_code = process.wait()
        if return_code != 0 or broken_pipe:
            error_log.seek(0)
            detail = error_log.read(65536).decode("utf-8", errors="replace").strip()
            raise KGGError(f"FFmpeg 转码失败（退出码 {return_code}）：{detail or '无错误详情'}")


def convert_one(
    input_path: Path,
    output_path: Path,
    header: KGGHeader,
    ekey: str,
    ffmpeg: str | None,
    ffprobe: str | None,
    bitrate: str,
    overwrite: bool,
) -> str:
    if output_path.exists() and not overwrite:
        return "已跳过（输出已存在）"

    cipher = create_qmc2_cipher(ekey)
    decrypted_chunks = iter_decrypted_audio(input_path, header, cipher)
    try:
        first_chunk = next(decrypted_chunks)
    except StopIteration as exc:
        raise KGGError("加密音频数据为空") from exc

    audio_type = _describe_audio(first_chunk)
    all_chunks = itertools.chain((first_chunk,), decrypted_chunks)
    temporary_path = _temporary_output(output_path)
    try:
        if _is_mp3(first_chunk):
            _write_decrypted_mp3(all_chunks, temporary_path)
            action = "解密直出 MP3（未二次编码）"
        else:
            if ffmpeg is None:
                raise KGGError(
                    f"解密后为 {audio_type}，需要 FFmpeg 转 MP3，但当前环境找不到 ffmpeg"
                )
            _transcode_to_mp3(all_chunks, temporary_path, ffmpeg, bitrate)
            action = f"{audio_type} -> {bitrate} MP3"
        _verify_mp3(temporary_path, ffprobe)
        os.replace(temporary_path, output_path)
        return action
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def find_default_database() -> Path | None:
    explicit = os.environ.get("KGG_DB", "").strip()
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    if appdata:
        candidates.extend(
            [
                Path(appdata) / "KuGou8" / "KGMusicV3.db",
                Path(appdata) / "KuGou" / "KGMusicV3.db",
            ]
        )
    if localappdata:
        candidates.extend(
            [
                Path(localappdata) / "KuGou8" / "KGMusicV3.db",
                Path(localappdata) / "KuGou" / "KGMusicV3.db",
            ]
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def collect_inputs(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        return [input_path] if input_path.suffix.lower() == ".kgg" else []
    pattern = "**/*.kgg" if recursive else "*.kgg"
    return sorted(
        (path for path in input_path.glob(pattern) if path.is_file()),
        key=lambda path: str(path).casefold(),
    )


def _run_self_tests() -> None:
    aes_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    aes_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    aes_ciphertext = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    aes_plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert _aes_cbc_decrypt(aes_ciphertext, aes_key, aes_iv) == aes_plaintext
    assert _simple_make_key(106, 8) == bytes.fromhex("695646382b20150b")
    # x/crypto/tea NewCipherWithRounds(zero-key, 32) of an all-zero block.
    assert _tea_decrypt_block(bytes.fromhex("a889f798182d8083"), bytes(16)) == bytes(8)
    map_key = bytes((index * 29 + 17) & 0xFF for index in range(256))
    assert QMC2MapCipher(map_key).decrypt(b"\x00", 0) == b"\x1d"

    rc4_key = bytes((index * 7 + 3) & 0xFF for index in range(400))
    expected = bytes.fromhex("c5da5561b1a57eea4705518a8161de6a")
    assert QMC2RC4Cipher(rc4_key).decrypt(bytes(16), 0x1400) == expected
    print("自检通过：AES/TEA、QMC2 MAP、QMC2 RC4 基础向量正常。")


def build_parser() -> argparse.ArgumentParser:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent
    default_output = script_dir / "Mp3_Output"
    parser = argparse.ArgumentParser(
        description="批量解密酷狗 KGG v5 文件，并输出真正的 MP3。",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=default_input, help="KGG 文件或所在目录")
    parser.add_argument("--output", type=Path, default=default_output, help="MP3 输出目录")
    parser.add_argument("--db", type=Path, help="KGMusicV3.db 路径；省略时自动查找")
    parser.add_argument("--recursive", action="store_true", help="递归扫描输入目录")
    parser.add_argument("--overwrite", action="store_true", help="覆盖已经存在的同名 MP3")
    parser.add_argument(
        "--bitrate",
        choices=("128k", "192k", "256k", "320k"),
        default="320k",
        help="非 MP3 源经 FFmpeg 转码时的码率",
    )
    parser.add_argument("--ffmpeg", help="ffmpeg 可执行文件路径；省略时从 PATH 查找")
    parser.add_argument("--ffprobe", help="ffprobe 可执行文件路径；省略时从 PATH 查找")
    parser.add_argument("--dry-run", action="store_true", help="只检查文件头和数据库密钥，不生成 MP3")
    parser.add_argument("--self-test", action="store_true", help="运行内置算法向量测试后退出")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    # `conda run` captures child output as UTF-8; force that encoding so Chinese
    # status text is not mis-decoded through the legacy Windows GBK code page.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    if args.self_test:
        _run_self_tests()
        return 0

    input_path = args.input.expanduser().resolve()
    output_dir = args.output.expanduser().resolve()
    inputs = collect_inputs(input_path, args.recursive)
    if not inputs:
        print(f"错误：没有找到 .kgg 文件：{input_path}", file=sys.stderr)
        return 2

    db_path = args.db.expanduser().resolve() if args.db else find_default_database()
    if db_path is None or not db_path.is_file():
        print(
            "错误：未找到 KGMusicV3.db。可用 --db 指定，常见位置为：\n"
            r"  %APPDATA%\KuGou8\KGMusicV3.db",
            file=sys.stderr,
        )
        return 2

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
    print(f"输入：{input_path}")
    print(f"输出：{output_dir}")
    print(f"数据库：{db_path}")
    print(f"找到 {len(inputs)} 个 KGG 文件，正在加载数据库密钥……")

    try:
        key_map = load_key_map(db_path)
    except KGGError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    print(f"数据库中读取到 {len(key_map)} 条有效密钥。")

    headers: dict[Path, KGGHeader] = {}
    failures: list[tuple[Path, str]] = []
    missing_keys: list[tuple[Path, str]] = []
    for path in inputs:
        try:
            header = read_kgg_header(path)
            headers[path] = header
            if header.audio_hash not in key_map:
                missing_keys.append((path, header.audio_hash))
        except KGGError as exc:
            failures.append((path, str(exc)))

    available = len(headers) - len(missing_keys)
    print(f"密钥匹配：{available}/{len(inputs)}。")
    for path, audio_hash in missing_keys:
        print(f"  [缺密钥] {path.name}（audioHash={audio_hash}）")
        failures.append((path, "数据库中没有对应密钥；请先在酷狗中完整播放一次，再退出酷狗重试"))

    if args.dry_run:
        if failures:
            print(f"检查结束：可转换 {available} 个，失败/缺密钥 {len(failures)} 个。")
            return 1
        print(f"检查结束：{available} 个文件均具备转换条件。")
        return 0

    ffmpeg = args.ffmpeg or shutil.which("ffmpeg")
    ffprobe = args.ffprobe or shutil.which("ffprobe")
    successes = 0
    skipped = 0
    missing_paths = {path for path, _ in missing_keys}
    for index, path in enumerate(inputs, 1):
        if path not in headers or path in missing_paths:
            continue
        output_path = output_dir / f"{path.stem}.mp3"
        print(f"[{index}/{len(inputs)}] {path.name}")
        try:
            result = convert_one(
                path,
                output_path,
                headers[path],
                key_map[headers[path].audio_hash],
                ffmpeg,
                ffprobe,
                args.bitrate,
                args.overwrite,
            )
            if result.startswith("已跳过"):
                skipped += 1
            else:
                successes += 1
            print(f"  [完成] {result} -> {output_path.name}")
        except (KGGError, OSError) as exc:
            failures.append((path, str(exc)))
            print(f"  [失败] {exc}", file=sys.stderr)

    print("\n处理汇总：")
    print(f"  成功：{successes}")
    print(f"  跳过：{skipped}")
    print(f"  失败：{len(failures)}")
    if failures:
        for path, reason in failures:
            print(f"  - {path.name}: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
