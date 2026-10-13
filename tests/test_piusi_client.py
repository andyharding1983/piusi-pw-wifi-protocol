"""
Unit tests for the frame builder/parser and record decoder.

All test fixtures here are synthetic (hand-constructed), not taken from any
real capture -- see docs/PROTOCOL.md for how the field layout was originally
derived and cross-checked against real (anonymized-before-commit) data.
"""

import socket
import sys
import tempfile
import threading
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


def test_raw_log_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sub" / "raw.jsonl"
        log = pc.RawLog(path)
        log.write("tx", b"\xff\x10\x02abc")
        log.write("event", note="hello")
        log.close()
        entries = list(pc.read_raw_log(path))
        assert [(d, b, n) for _, d, b, n in entries] == [
            ("tx", b"\xff\x10\x02abc", ""),
            ("event", b"", "hello"),
        ]


def _fake_device(reply_chunks):
    """Local TCP server standing in for the bridge: answers the first
    request with reply_chunks (sent as separate segments), then waits."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    done = threading.Event()

    def serve():
        conn, _ = srv.accept()
        conn.recv(256)
        for chunk in reply_chunks:
            conn.sendall(chunk)
            threading.Event().wait(0.01)
        done.wait(5)
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], done


def test_received_bytes_logged_even_when_unparseable():
    # The destructive-read guarantee: whatever the device sends must hit
    # the log even if our parser can't make sense of it.
    garbage = b"\xff\xff\x10\x02not-a-valid-record"
    port, done = _fake_device([garbage])
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        client = pc.PiusiClient("127.0.0.1", port=port, raw_log_path=log_path)
        client.connect()
        assert client.query_next_record() is None
        done.set()
        client.close()
        rx = b"".join(b for _, d, b, _ in pc.read_raw_log(log_path) if d == "rx")
        tx = [b for _, d, b, _ in pc.read_raw_log(log_path) if d == "tx"]
        assert rx == garbage
        assert tx == [pc.build_frame("123456", pc.CMD_QUERY)]


def test_split_reply_reassembled_and_logged():
    record = _build_synthetic_record()
    frame = pc.build_frame("123456", pc.CMD_RECORD, record)
    port, done = _fake_device([frame[:10], frame[10:]])
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        client = pc.PiusiClient("127.0.0.1", port=port, raw_log_path=log_path)
        client.connect()
        rec = client.query_next_record()
        done.set()
        client.close()
        assert rec is not None and rec.key == "TESTKEY1"
        rx = b"".join(b for _, d, b, _ in pc.read_raw_log(log_path) if d == "rx")
        assert rx == frame


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
