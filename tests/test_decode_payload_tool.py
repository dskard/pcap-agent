"""Unit tests for the decode_payload tool."""

from __future__ import annotations

import gzip
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
