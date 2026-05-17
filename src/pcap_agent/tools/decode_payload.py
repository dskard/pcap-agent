"""Tool for decompressing hex-encoded payloads from PCAP streams."""

from __future__ import annotations

import zlib

_MAX_BYTES = 64 * 1024

_GZIP_MAGIC = b"\x1f\x8b"
_ZLIB_MAGICS = {b"\x78\x9c", b"\x78\x01", b"\x78\xda"}


def decode_payload(
    data: str,
    format: str = "auto",  # noqa: A002
    member: int | None = None,
) -> dict:
    """Decompress a hex-encoded payload string.

    Parameters
    ----------
    data:
        Hex-encoded bytes (e.g. output of DuckDB ``hex()`` or ``reassemble_stream``).
    format:
        ``'auto'`` detects gzip/zlib via magic bytes. ``'deflate'`` forces raw DEFLATE.
    member:
        For multi-member gzip streams, select the 0-based member index to return.
        Defaults to 0 (first member).
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
        if raw[:2] == _GZIP_MAGIC:
            return _decompress_gzip(raw, member=member or 0)
        if raw[:2] in _ZLIB_MAGICS:
            return _decompress_zlib(raw)
        return {
            "error": "Could not auto-detect compression format.",
            "hint": "try format='deflate'",
        }

    return {"error": f"Unknown format: {format!r}", "hint": "Use 'auto', 'deflate'."}


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
