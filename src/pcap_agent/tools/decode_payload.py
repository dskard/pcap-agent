"""Tool for decompressing hex-encoded payloads from PCAP streams."""

from __future__ import annotations

import io
import zipfile
import zlib

_MAX_BYTES = 64 * 1024

_GZIP_MAGIC = b"\x1f\x8b"
_ZLIB_MAGICS = {b"\x78\x9c", b"\x78\x01", b"\x78\xda"}
_ZIP_MAGIC = b"\x50\x4b\x03\x04"


def decode_payload(
    data: str,
    format: str = "auto",  # noqa: A002
    member: int | str | None = None,
) -> dict:
    """Decompress or decode a hex-encoded payload string.

    Parameters
    ----------
    data:
        Hex-encoded bytes (e.g. output of DuckDB ``hex()`` or ``reassemble_stream``).
    format:
        ``'auto'`` detects gzip/zlib/zip via magic bytes; ``'deflate'`` forces DEFLATE.
    member:
        ZIP: a filename string to extract that member (omit to list all members).
        gzip: a 0-based integer index to select a multi-member stream member.
    """
    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        return {
            "error": f"Invalid hex input: {exc}",
            "hint": "Provide a valid hex string.",
        }

    if format == "deflate":
        return _decompress_deflate(raw)

    if format == "auto":
        if raw[:4] == _ZIP_MAGIC:
            return _handle_zip(raw, member=member if isinstance(member, str) else None)
        if raw[:2] == _GZIP_MAGIC:
            gzip_member = member if isinstance(member, int) else 0
            return _decompress_gzip(raw, member=gzip_member)
        if raw[:2] in _ZLIB_MAGICS:
            return _decompress_zlib(raw)
        return {
            "error": "Could not auto-detect compression format.",
            "hint": "try format='deflate'",
        }

    return {"error": f"Unknown format: {format!r}", "hint": "Use 'auto', 'deflate'."}


def _handle_zip(raw: bytes, member: str | None = None) -> dict:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        return {
            "error": f"ZIP parse failed: {exc}",
            "hint": "Verify the payload is a valid ZIP archive.",
        }

    if member is None:
        return {
            "members": [
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                }
                for info in zf.infolist()
            ]
        }

    info_map = {info.filename: info for info in zf.infolist()}
    if member not in info_map:
        return {"error": f"Member {member!r} not found.", "hint": "list members first"}

    info = info_map[member]
    if info.file_size > _MAX_BYTES:
        sz = info.file_size
        msg = f"Member {member!r} is {sz} bytes, exceeding the {_MAX_BYTES}-byte limit."
        return {
            "error": msg,
            "hint": "Extract a smaller member or use a different tool.",
        }

    data = zf.read(member)
    if len(data) > _MAX_BYTES:
        sz = len(data)
        msg = f"Member {member!r} decompressed to {sz} bytes, exceeding {_MAX_BYTES}."
        return {
            "error": msg,
            "hint": "Extract a smaller member or use a different tool.",
        }
    return _encode_output(data)


def _decompress_gzip(raw: bytes, member: int = 0) -> dict:
    if member < 0:
        return {"error": f"Member index must be >= 0, got {member}."}
    try:
        members = list(_iter_gzip_members(raw))
        if not members:
            return {"error": "gzip decompression failed: no members found"}
        if member >= len(members):
            n = len(members)
            return {
                "error": f"Member {member} out of range: stream has {n} member(s).",
                "hint": f"Use a member index between 0 and {n - 1}.",
            }
        target = members[member]
    except zlib.error as exc:
        return {"error": f"gzip decompression failed: {exc}"}
    return _encode_output(target)


def _iter_gzip_members(data: bytes):
    """Yield decompressed bytes for each gzip member in a concatenated stream."""
    remaining = data
    while remaining:
        d = zlib.decompressobj(wbits=31)  # 31 = 15 + 16 enables gzip format
        yield d.decompress(remaining, max_length=_MAX_BYTES + 1)
        # If max_length was hit, d.unused_data is empty and d.unconsumed_tail
        # holds the remaining compressed bytes. Drain them (discarding output)
        # until d.unused_data points to the next member.
        tail = d.unconsumed_tail
        while tail:
            d.decompress(tail, max_length=_MAX_BYTES + 1)
            if d.unused_data:
                break
            tail = d.unconsumed_tail
        remaining = d.unused_data
        if not remaining:
            break


def _decompress_zlib(raw: bytes) -> dict:
    try:
        d = zlib.decompressobj()
        decompressed = d.decompress(raw, max_length=_MAX_BYTES + 1)
    except zlib.error as exc:
        return {"error": f"zlib decompression failed: {exc}"}
    return _encode_output(decompressed)


def _decompress_deflate(raw: bytes) -> dict:
    try:
        d = zlib.decompressobj(wbits=-15)
        decompressed = d.decompress(raw, max_length=_MAX_BYTES + 1)
    except zlib.error as exc:
        return {"error": f"deflate decompression failed: {exc}"}
    return _encode_output(decompressed)


def _encode_output(data: bytes) -> dict:
    truncated = False
    if len(data) > _MAX_BYTES:
        data = data[:_MAX_BYTES]
        truncated = True

    try:
        content = data.decode("utf-8")
        content_encoding = "utf-8"
    except UnicodeDecodeError:
        content = data.hex()
        content_encoding = "hex"

    return {
        "content": content,
        "content_encoding": content_encoding,
        "truncated": truncated,
    }
