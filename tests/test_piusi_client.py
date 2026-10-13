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


def to_bcd(n):
    return ((n // 10) << 4) | (n % 10)


def _build_synthetic_record(
    day=15, month=3, year=26, hour=9, minute=30,
    person="TESTOP", key="TESTKEY1", litres=12.34, legacy_extra=None,
):
    """Hand-builds an unstuffed '+' payload matching the documented layout,
    independent of parse_uplift_record, so the test can catch decode bugs.
    32 bytes; or 33 with legacy_extra inserted after the month (the layout
    originally documented, before the DLE-stuffing explanation)."""
    qty = round(litres * 100)
    date = bytes([to_bcd(day), to_bcd(month)])
    if legacy_extra is not None:
        date += bytes([legacy_extra])
    date += bytes([to_bcd(year)])
    payload = (
        date
        + bytes([to_bcd(hour), to_bcd(minute)])
        + b"\x01\x02\x03\x04"  # unknown bytes
        + person.encode("ascii").ljust(10)
        + key.encode("ascii").ljust(10)
        + bytes([to_bcd(qty // 10000), to_bcd(qty // 100 % 100), to_bcd(qty % 100)])
    )
    assert len(payload) == (33 if legacy_extra is not None else 32)
    return payload


def _decode_one(frame_bytes):
    frames = pc.FrameDecoder().feed(frame_bytes)
    assert len(frames) == 1, frames
    return frames[0]


def test_parse_uplift_record_synthetic():
    payload = _build_synthetic_record()
    rec = pc.parse_uplift_record(payload)
    assert rec.layout == "dle"
    assert (rec.day, rec.month, rec.year, rec.hour, rec.minute) == (15, 3, 26, 9, 30)
    assert rec.unknown_date_byte is None
    assert rec.unknown_bytes == b"\x01\x02\x03\x04"
    assert rec.person == "TESTOP"
    assert rec.key == "TESTKEY1"
    assert abs(rec.litres - 12.34) < 1e-9


def test_parse_uplift_record_small_quantity():
    rec = pc.parse_uplift_record(_build_synthetic_record(litres=0.41))
    assert abs(rec.litres - 0.41) < 1e-9


def test_quantity_over_100_litres():
    # Regression: the old parser read only the last two BCD bytes, so
    # 150.00 L (01 50 00) came out as 50.00 L.
    rec = pc.parse_uplift_record(_build_synthetic_record(litres=150.0))
    assert abs(rec.litres - 150.0) < 1e-9
    rec = pc.parse_uplift_record(_build_synthetic_record(litres=1234.56))
    assert abs(rec.litres - 1234.56) < 1e-9


def test_timestamp_property():
    payload = _build_synthetic_record(day=15, month=3, year=26, hour=9, minute=30)
    ts = pc.parse_uplift_record(payload).timestamp
    assert ts is not None
    assert (ts.year, ts.month, ts.day, ts.hour, ts.minute) == (2026, 3, 15, 9, 30)


def test_invalid_bcd_raises():
    payload = bytearray(_build_synthetic_record())
    payload[0] = 0x1A
    try:
        pc.parse_uplift_record(bytes(payload))
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-BCD day byte")


def test_wrong_length_raises():
    try:
        pc.parse_uplift_record(_build_synthetic_record()[:31])
    except ValueError:
        return
    raise AssertionError("expected ValueError for a 31-byte record")


def test_legacy_33_byte_layout_still_decodes():
    # If the DLE-stuffing theory is wrong, unstuffed records would still be
    # 33 bytes with a real extra date byte. Those must decode, not be lost.
    payload = _build_synthetic_record(month=3, legacy_extra=0x03, litres=150.0)
    rec = pc.parse_uplift_record(payload)
    assert rec.layout == "legacy"
    assert rec.unknown_date_byte == 0x03
    assert (rec.day, rec.month, rec.year) == (15, 3, 26)
    assert rec.key == "TESTKEY1"
    assert abs(rec.litres - 150.0) < 1e-9


def test_build_frame_stuffs_dle():
    params = b"\x10\x03\x10"
    frame = pc.build_frame("123456", pc.CMD_RECORD, params)
    inner = frame[frame.index(pc.DLE_STX) + 2:]
    assert b"\x10\x10\x03\x10\x10" in inner
    f = _decode_one(frame)
    assert f.params == params
    assert f.checksum_matches in ("unstuffed", "both")


def test_october_record_on_the_wire():
    # The shape seen in the original capture: month 0x10 arrives as 10 10,
    # which was previously read as a fourth date byte. Built by hand (not
    # via build_frame) so it doesn't depend on our own stuffing code.
    record = _build_synthetic_record(day=6, month=10, year=26, hour=14, minute=5)
    assert record[:3] == bytes([0x06, 0x10, 0x26])
    wire_payload = b"123456+" + record.replace(b"\x10", b"\x10\x10")
    assert b"\x06\x10\x10\x26" in wire_payload
    cks = pc.checksum(b"123456+" + record)
    raw = b"\xff" * 5 + b"\x10\x02" + wire_payload + b"\x10\x03" + bytes([cks]) + b"\xff"
    rec = pc.parse_uplift_record(_decode_one(raw).params)
    assert (rec.day, rec.month, rec.year, rec.hour, rec.minute) == (6, 10, 26, 14, 5)
    assert rec.key == "TESTKEY1"


def test_record_at_1003_in_october():
    # month=10, hour=10, minute=03 -> unstuffed 10 26 10 03 contains the
    # ETX sequence; the old find(b"\x10\x03") truncated the frame here.
    record = _build_synthetic_record(day=6, month=10, year=26, hour=10, minute=3)
    rec = pc.parse_uplift_record(_decode_one(pc.build_frame("123456", pc.CMD_RECORD, record)).params)
    assert (rec.month, rec.hour, rec.minute) == (10, 10, 3)
    assert rec.person == "TESTOP"


def test_decoder_handles_byte_by_byte_and_back_to_back_frames():
    rec_frame = pc.build_frame("123456", pc.CMD_RECORD, _build_synthetic_record(month=10, litres=150.0))
    ack = pc.build_frame("123456", pc.CMD_POLL_ACK)
    stream = b"\xff\xff" + rec_frame + ack + rec_frame
    dec = pc.FrameDecoder()
    frames = []
    for b in stream:
        frames += dec.feed(bytes([b]))
    assert [f.command for f in frames] == [pc.CMD_RECORD, pc.CMD_POLL_ACK, pc.CMD_RECORD]
    assert all(f.checksum_matches is not None for f in frames)


def test_stuffed_checksum_byte():
    # Find a payload whose checksum is itself 0x10, which must be stuffed too.
    for c in range(256):
        params = bytes([c])
        if pc.checksum(b"123456P" + params) == 0x10:
            break
    frame = pc.build_frame("123456", pc.CMD_POLL, params)
    assert frame.endswith(b"\x10\x03\x10\x10\xff")
    f = _decode_one(frame)
    assert f.params == params and f.checksum == 0x10


def test_checksum_variant_reported():
    # Device-side checksum over the *stuffed* bytes (one stuffed 0x10, so
    # the two variants differ) should be identified as such.
    record = _build_synthetic_record(month=10)
    wire_payload = b"123456+" + record.replace(b"\x10", b"\x10\x10")
    assert wire_payload.count(b"\x10") % 4 != 0  # odd number of stuffed bytes
    cks = pc.checksum(wire_payload)
    raw = b"\x10\x02" + wire_payload + b"\x10\x03" + pc.dle_stuff(bytes([cks])) + b"\xff"
    assert _decode_one(raw).checksum_matches == "stuffed"


def test_resync_on_new_stx_mid_frame():
    good = pc.build_frame("123456", pc.CMD_POLL_ACK)
    frames = pc.FrameDecoder().feed(b"\x10\x02123" + good)
    assert [f.command for f in frames] == [pc.CMD_POLL_ACK]


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


def _fake_device(reply_chunks, delay=0.0):
    """Local TCP server standing in for the bridge: answers the first
    request with reply_chunks (sent as separate segments, after delay
    seconds), then records anything else sent until told to stop."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    done = threading.Event()

    def serve():
        conn, _ = srv.accept()
        conn.recv(256)
        done.wait(delay)
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
        client = pc.PiusiClient("127.0.0.1", "123456", port=port, raw_log_path=log_path)
        client.connect()
        assert client.query_next_record() is None
        done.set()
        client.close()
        rx = b"".join(b for _, d, b, _ in pc.read_raw_log(log_path) if d == "rx")
        tx = [b for _, d, b, _ in pc.read_raw_log(log_path) if d == "tx"]
        assert rx == garbage
        assert tx == [pc.build_frame("123456", pc.CMD_QUERY)]


def test_undecodable_record_raises_but_is_logged():
    bad = pc.build_frame("123456", pc.CMD_RECORD, b"\xaa" * 32)  # not BCD
    port, done = _fake_device([bad])
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        client = pc.PiusiClient("127.0.0.1", port=port, raw_log_path=log_path)
        client.connect()
        try:
            client.query_next_record()
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
        done.set()
        client.close()
        rx = b"".join(b for _, d, b, _ in pc.read_raw_log(log_path) if d == "rx")
        assert rx == bad


def test_late_record_is_returned_not_lost():
    # The device answers after our recv timeout. The record must come back
    # from the next query_next_record() -- without sending a second C,
    # which would destructively pop a *different* record.
    frame = pc.build_frame("123456", pc.CMD_RECORD, _build_synthetic_record())
    port, done = _fake_device([frame], delay=0.4)
    saved_gap = pc.MIN_REQUEST_GAP
    pc.MIN_REQUEST_GAP = 0.5
    try:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "raw.jsonl"
            client = pc.PiusiClient("127.0.0.1", port=port, raw_log_path=log_path, recv_timeout=0.2)
            client.connect()
            assert client.query_next_record() is None
            threading.Event().wait(0.4)
            rec = client.query_next_record()
            done.set()
            client.close()
            assert rec is not None and rec.key == "TESTKEY1"
            tx = [b for _, d, b, _ in pc.read_raw_log(log_path) if d == "tx"]
            assert tx == [pc.build_frame("123456", pc.CMD_QUERY)]
    finally:
        pc.MIN_REQUEST_GAP = saved_gap


def test_split_reply_reassembled_and_logged():
    record = _build_synthetic_record()
    frame = pc.build_frame("123456", pc.CMD_RECORD, record)
    port, done = _fake_device([frame[:10], frame[10:]])
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        client = pc.PiusiClient("127.0.0.1", "123456", port=port, raw_log_path=log_path)
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
