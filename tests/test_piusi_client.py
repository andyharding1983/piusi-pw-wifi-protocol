"""
Unit tests for the frame builder/parser and record decoder.

All test fixtures here are synthetic (hand-constructed), not taken from any
real capture -- see docs/PROTOCOL.md for how the field layout was originally
derived and cross-checked against real (anonymized-before-commit) data.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import piusi_client as pc  # noqa: E402


def manual_xor_checksum(payload: bytes) -> int:
    value = 0
    for b in payload:
        value ^= b
    return value


def test_checksum_matches_manual_xor():
    payload = b"123456D" + pc.HANDSHAKE_PARAMS
    assert pc.checksum(payload) == manual_xor_checksum(payload)


def test_build_and_parse_round_trip():
    frame = pc.build_frame("654321", pc.CMD_QUERY)
    parsed = pc.parse_frame(frame)
    assert parsed is not None
    addr, cmd, params = parsed
    assert addr == "654321"
    assert cmd == pc.CMD_QUERY
    assert params == b""


def test_parse_frame_rejects_garbage():
    assert pc.parse_frame(b"\xff\xff\xff not a real frame") is None


def test_build_frame_checksum_changes_with_address():
    frame_a = pc.build_frame("111111", pc.CMD_POLL)
    frame_b = pc.build_frame("222222", pc.CMD_POLL)
    assert frame_a != frame_b


def _build_synthetic_record(
    day=15, month=3, unknown=0x10, year=26, hour=9, minute=30,
    person="TESTOP", key="TESTKEY1", litres=12.34,
):
    """Hand-builds a 33-byte '+' payload matching the documented layout,
    independent of parse_uplift_record, so the test can catch decode bugs."""
    qty_raw = round(litres * 100)
    qty_hi, qty_lo = divmod(qty_raw, 100)

    def to_bcd(n):
        return ((n // 10) << 4) | (n % 10)

    header = bytes([to_bcd(day), to_bcd(month), unknown, to_bcd(year), to_bcd(hour), to_bcd(minute)])
    header += b"\x00\x00\x00\x00"  # bytes 6-9, unknown/unused in this test
    person_field = person.encode("ascii").ljust(10)
    key_field = key.encode("ascii").ljust(10)
    tail = bytes([0x00, to_bcd(qty_hi), to_bcd(qty_lo)])
    payload = header + person_field + key_field + tail
    assert len(payload) == 33
    return payload


def test_parse_uplift_record_synthetic():
    payload = _build_synthetic_record()
    rec = pc.parse_uplift_record(payload)
    assert rec.day == 15
    assert rec.month == 3
    assert rec.year == 26
    assert rec.hour == 9
    assert rec.minute == 30
    assert rec.person == "TESTOP"
    assert rec.key == "TESTKEY1"
    assert abs(rec.litres - 12.34) < 1e-9


def test_parse_uplift_record_small_quantity():
    # regression test for the offset-by-one bug: the 2 BCD quantity bytes
    # are the LAST two of the 3-byte tail (tail[0] is always 0x00 padding),
    # i.e. params[31:33], not params[30:32].
    payload = _build_synthetic_record(litres=0.41, person="TEST", key="TEST")
    rec = pc.parse_uplift_record(payload)
    assert abs(rec.litres - 0.41) < 1e-9


def test_timestamp_property():
    payload = _build_synthetic_record(day=15, month=3, year=26, hour=9, minute=30)
    rec = pc.parse_uplift_record(payload)
    ts = rec.timestamp
    assert ts is not None
    assert (ts.year, ts.month, ts.day, ts.hour, ts.minute) == (2026, 3, 15, 9, 30)


if __name__ == "__main__":
    import inspect

    failures = 0
    tests = {name: fn for name, fn in globals().items() if name.startswith("test_")}
    for name, fn in tests.items():
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
