"""Unit tests for the decode_payload tool."""

from __future__ import annotations

import gzip
import io
import zipfile
import zlib

from pcap_agent.tools.decode_payload import decode_payload

_MAX_BYTES = 64 * 1024


class TestGzipRoundTrip:
    def test_gzip_roundtrip(self):
        original = b"Hello, world!"
        compressed = gzip.compress(original)
        hex_data = compressed.hex()

        result = decode_payload(hex_data)

        assert "error" not in result
        assert result["content"] == "Hello, world!"
        assert result["content_encoding"] == "utf-8"
        assert result["truncated"] is False


class TestZlibRoundTrip:
    def test_zlib_roundtrip(self):
        original = b"zlib compressed data"
        compressed = zlib.compress(original)
        hex_data = compressed.hex()

        result = decode_payload(hex_data)

        assert "error" not in result
        assert result["content"] == "zlib compressed data"
        assert result["content_encoding"] == "utf-8"
        assert result["truncated"] is False


class TestDeflateRoundTrip:
    def test_deflate_roundtrip(self):
        original = b"raw deflate data"
        compressed = zlib.compress(original)[2:-4]  # strip zlib header/checksum
        hex_data = compressed.hex()

        result = decode_payload(hex_data, format="deflate")

        assert "error" not in result
        assert result["content"] == "raw deflate data"
        assert result["content_encoding"] == "utf-8"
        assert result["truncated"] is False


class TestAutoDetection:
    def test_auto_detects_gzip(self):
        compressed = gzip.compress(b"auto gzip")
        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["content"] == "auto gzip"

    def test_auto_detects_zlib_78_9c(self):
        compressed = zlib.compress(b"auto zlib", level=6)
        assert compressed[:2] == b"\x78\x9c"
        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["content"] == "auto zlib"

    def test_auto_detects_zlib_78_01(self):
        compressed = zlib.compress(b"auto zlib low", level=1)
        assert compressed[:2] == b"\x78\x01"
        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["content"] == "auto zlib low"

    def test_auto_detects_zlib_78_da(self):
        compressed = zlib.compress(b"auto zlib best", level=9)
        assert compressed[:2] == b"\x78\xda"
        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["content"] == "auto zlib best"

    def test_auto_unknown_returns_structured_error(self):
        # Plain text has no compression magic bytes
        hex_data = b"no magic here".hex()
        result = decode_payload(hex_data)

        assert "error" in result
        assert "hint" in result
        assert "deflate" in result["hint"]


class TestTruncation:
    def test_truncation_at_64kb(self):
        original = b"A" * (65 * 1024)
        compressed = gzip.compress(original)

        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["truncated"] is True
        assert len(result["content"].encode()) == _MAX_BYTES

    def test_no_truncation_at_exactly_64kb(self):
        original = b"B" * _MAX_BYTES
        compressed = gzip.compress(original)

        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["truncated"] is False
        assert len(result["content"].encode()) == _MAX_BYTES


class TestBinaryHexFallback:
    def test_non_utf8_returned_as_hex(self):
        binary = bytes(range(256))  # contains non-UTF-8 bytes
        compressed = gzip.compress(binary)

        result = decode_payload(compressed.hex())

        assert "error" not in result
        assert result["content_encoding"] == "hex"
        assert result["content"] == binary.hex()


class TestInvalidHex:
    def test_invalid_hex_returns_structured_error(self):
        result = decode_payload("not-valid-hex!")

        assert "error" in result
        assert "hint" in result

    def test_odd_length_hex_returns_error(self):
        result = decode_payload("abc")  # odd-length hex string

        assert "error" in result


class TestMemberSelection:
    def test_member_0_is_default(self):
        compressed = gzip.compress(b"member zero")

        result_default = decode_payload(compressed.hex())
        result_explicit = decode_payload(compressed.hex(), member=0)

        assert result_default["content"] == result_explicit["content"]

    def test_multi_member_gzip_member_selection(self):
        member0 = gzip.compress(b"first member")
        member1 = gzip.compress(b"second member")
        combined = (member0 + member1).hex()

        result0 = decode_payload(combined, member=0)
        result1 = decode_payload(combined, member=1)

        assert result0["content"] == "first member"
        assert result1["content"] == "second member"

    def test_out_of_bounds_member_returns_error(self):
        compressed = gzip.compress(b"only one member")

        result = decode_payload(compressed.hex(), member=99)

        assert "error" in result
        assert "hint" in result

    def test_negative_member_returns_error(self):
        compressed = gzip.compress(b"single member")

        result = decode_payload(compressed.hex(), member=-1)

        assert "error" in result

    def test_oversized_member_0_does_not_drop_member_1(self):
        large_member0 = gzip.compress(b"X" * (65 * 1024))  # exceeds _MAX_BYTES
        member1 = gzip.compress(b"second member data")
        combined = (large_member0 + member1).hex()

        result = decode_payload(combined, member=1)

        assert "error" not in result
        assert result["content"] == "second member data"


def _make_zip(*members: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


class TestZipMemberListing:
    def test_zip_magic_bytes_trigger_member_listing(self):
        zip_bytes = _make_zip(("hello.txt", b"Hello"), ("world.txt", b"World"))
        result = decode_payload(zip_bytes.hex())

        assert "error" not in result
        assert "members" in result
        members = result["members"]
        assert len(members) == 2
        names = {m["name"] for m in members}
        assert names == {"hello.txt", "world.txt"}
        for m in members:
            assert "size" in m
            assert "compressed_size" in m


class TestZipMemberExtraction:
    def test_extract_text_member_by_name(self):
        zip_bytes = _make_zip(("readme.txt", b"Hello from ZIP"))
        result = decode_payload(zip_bytes.hex(), member="readme.txt")

        assert "error" not in result
        assert result["content"] == "Hello from ZIP"
        assert result["content_encoding"] == "utf-8"

    def test_extract_binary_member_returns_hex(self):
        binary_data = bytes(range(256))
        zip_bytes = _make_zip(("data.bin", binary_data))
        result = decode_payload(zip_bytes.hex(), member="data.bin")

        assert "error" not in result
        assert result["content_encoding"] == "hex"
        assert result["content"] == binary_data.hex()

    def test_member_exceeding_64kb_returns_hard_error(self):
        large_data = b"X" * (_MAX_BYTES + 1)
        zip_bytes = _make_zip(("big.txt", large_data))
        result = decode_payload(zip_bytes.hex(), member="big.txt")

        assert "error" in result
        assert "truncated" not in result


class TestZipMemberNotFound:
    def test_nonexistent_member_returns_structured_error(self):
        zip_bytes = _make_zip(("exists.txt", b"data"))
        result = decode_payload(zip_bytes.hex(), member="does_not_exist.txt")

        assert "error" in result
        assert result.get("hint") == "list members first"


class TestDebugLogging:
    def test_debug_log_includes_member(self, caplog):
        import logging

        compressed = gzip.compress(b"hello")
        with caplog.at_level(logging.DEBUG, logger="pcap_agent.tools.decode_payload"):
            decode_payload(compressed.hex(), member=0)

        assert any("member=0" in r.message for r in caplog.records)
