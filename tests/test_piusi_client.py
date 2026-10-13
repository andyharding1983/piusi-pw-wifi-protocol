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

pc.MIN_REQUEST_GAP = 0.0  # no need for the real device's pacing against the fake


def manual_xor_checksum(payload: bytes) -> int:
    value = 0
    for b in payload:
        value ^= b
    return value


def test_checksum_matches_manual_xor():
    payload = b"123456D" + pc.HANDSHAKE_PARAMS
    assert pc.checksum(payload) == manual_xor_checksum(payload)


def test_build_and_parse_round_trip():
    frame = pc.build_frame("654321", pc.CMD_CONFIRM)
    parsed = pc.parse_frame(frame)
    assert parsed is not None
    addr, cmd, params = parsed
    assert addr == "654321"
    assert cmd == pc.CMD_CONFIRM
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
    person="TESTOP", key="TESTKEY1", litres=12.34, legacy_extra=None, second=1,
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
        + bytes([second]) + b"\x02\x03\x04"  # seconds (binary) + 3 unknown
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
    assert rec.second == 1
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
    assert (ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second) == (2026, 3, 15, 9, 30, 1)


def test_seconds_byte_is_binary_not_bcd():
    # 0x2e = 46 seconds; as BCD it would be invalid.
    rec = pc.parse_uplift_record(_build_synthetic_record(second=0x2E))
    assert rec.second == 46 and rec.timestamp.second == 46
    rec = pc.parse_uplift_record(_build_synthetic_record(second=0x3C))  # 60: not a second
    assert rec.second is None and rec.timestamp.second == 0


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


class FakeBowser:
    """
    Local TCP stand-in for the device, following the real protocol:
    D -> A;  P -> '+' (oldest record) or '0';  C -> delete oldest, no reply.

    Flakiness knobs: ignore_polls / ignore_confirms (silently drop the first
    N of each), split (send each reply in two TCP segments), close_after
    (drop the connection after N received commands).
    """

    def __init__(self, records=(), unit="123456", ignore_polls=0, ignore_confirms=0,
                 split=False, close_after=None):
        self.records = list(records)
        self.unit = unit
        self.ignore_polls = ignore_polls
        self.ignore_confirms = ignore_confirms
        self.split = split
        self.close_after = close_after
        self.received = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._srv.close()

    def _reply(self, cmd):
        if cmd == pc.CMD_HANDSHAKE:
            return pc.build_frame(self.unit, pc.CMD_HANDSHAKE_ACK)
        if cmd == pc.CMD_POLL:
            if self.ignore_polls:
                self.ignore_polls -= 1
                return None
            if self.records:
                return pc.build_frame(self.unit, pc.CMD_RECORD, self.records[0])
            return pc.build_frame(self.unit, pc.CMD_POLL_ACK)
        if cmd == pc.CMD_CONFIRM:
            if self.ignore_confirms:
                self.ignore_confirms -= 1
            elif self.records:
                self.records.pop(0)
        return None

    def _handle_connection(self, conn):
        dec = pc.FrameDecoder()
        conn.settimeout(0.05)
        while not self._stop.is_set():
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            for f in dec.feed(data):
                self.received.append(f.command)
                if self.close_after is not None and len(self.received) >= self.close_after:
                    return
                reply = self._reply(f.command)
                if reply and self.split:
                    conn.sendall(reply[:10])
                    threading.Event().wait(0.02)
                    conn.sendall(reply[10:])
                elif reply:
                    conn.sendall(reply)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            try:
                self._handle_connection(conn)
            finally:
                conn.close()


def _client(dev, log_path, **kw):
    kw.setdefault("recv_timeout", 0.5)
    c = pc.PiusiClient("127.0.0.1", dev.unit, port=dev.port, raw_log_path=log_path, **kw)
    c.connect()
    assert c.handshake()
    return c


def _log_entries(path, direction=None):
    return [e for e in pc.read_raw_log(path) if direction is None or e[1] == direction]


R1 = _build_synthetic_record(person="ONE", litres=1.0, second=5)
R2 = _build_synthetic_record(person="TWO", litres=2.0, second=6)

P, C, D = pc.CMD_POLL, pc.CMD_CONFIRM, pc.CMD_HANDSHAKE


def test_fetch_and_confirm_cycle_matches_official_sequence():
    with FakeBowser([R1, R2]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        f1 = c.fetch_next()
        assert f1.params == R1
        c.confirm(f1)
        f2 = c.fetch_next()
        assert f2.params == R2
        c.confirm(f2)
        assert c.fetch_next() is None
        c.close()
        assert dev.received == [D, P, C, P, C, P]
        assert dev.records == []


def test_fetch_is_non_destructive_without_confirm():
    with FakeBowser([R1, R2]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        assert c.fetch_next().params == R1
        assert c.fetch_next().params == R1  # same record again
        c.close()
        assert C not in dev.received
        assert dev.records == [R1, R2]


def test_confirm_refuses_blind_or_stale():
    with FakeBowser([R1]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        for bad in (None, pc.Frame("123456", b"+", R1, 0, None)):
            try:
                c.confirm(bad)
                raise AssertionError("confirm accepted a record that wasn't just fetched")
            except ValueError:
                pass
        old = c.fetch_next()
        c.fetch_next()  # re-fetch: `old` is now stale
        try:
            c.confirm(old)
            raise AssertionError("confirm accepted a stale frame")
        except ValueError:
            pass
        c.close()
        assert C not in dev.received
        assert dev.records == [R1]


def test_empty_queue_sends_no_confirm():
    with FakeBowser([]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        assert c.fetch_next() is None
        c.close()
        assert dev.received == [D, P]


def test_no_reply_raises_and_deletes_nothing():
    with FakeBowser([R1], ignore_polls=1) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        try:
            c.fetch_next()
            raise AssertionError("expected NoReplyError")
        except pc.NoReplyError:
            pass
        assert c.fetch_next().params == R1  # still there
        c.close()
        assert C not in dev.received


def test_connection_drop_ends_cleanly():
    # Regression: a dropped connection used to spin, logging hundreds of
    # "peer closed connection" events.
    with FakeBowser([R1], close_after=2) as dev, tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        c = _client(dev, log_path)
        try:
            c.fetch_next()
            raise AssertionError("expected ConnectionError")
        except ConnectionError:
            pass
        try:
            c.fetch_next()
            raise AssertionError("expected ConnectionError on a dead connection")
        except ConnectionError:
            pass
        c.close()
        notes = [e[3] for e in _log_entries(log_path, "event")]
        assert sum("peer closed" in n or "recv failed" in n for n in notes) == 1, notes
        assert dev.records == [R1]


def test_split_reply_reassembled_and_logged():
    with FakeBowser([R1], split=True) as dev, tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        c = _client(dev, log_path)
        f = c.fetch_next()
        c.close()
        assert f.params == R1
        rx = b"".join(e[2] for e in _log_entries(log_path, "rx"))
        assert pc.build_frame("123456", pc.CMD_RECORD, R1) in rx


def test_undecodable_record_logged_and_left_on_device():
    bad = b"\xaa" * 32  # not BCD
    with FakeBowser([bad]) as dev, tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "raw.jsonl"
        c = _client(dev, log_path)
        try:
            list(c.drain_queue())
            raise AssertionError("expected ValueError")
        except ValueError:
            pass
        c.close()
        assert C not in dev.received
        assert dev.records == [bad]
        rx = b"".join(e[2] for e in _log_entries(log_path, "rx"))
        assert pc.build_frame("123456", pc.CMD_RECORD, bad) in rx


def test_drain_queue_confirms_each_record_after_it_is_consumed():
    with FakeBowser([R1, R2]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        seen = []
        for rec in c.drain_queue():
            assert dev.records[0] == rec.raw  # not yet deleted while we hold it
            seen.append(rec.person)
        c.close()
        assert seen == ["ONE", "TWO"]
        assert dev.records == []


def test_drain_queue_break_leaves_current_record():
    with FakeBowser([R1, R2]) as dev, tempfile.TemporaryDirectory() as tmp:
        c = _client(dev, Path(tmp) / "raw.jsonl")
        for rec in c.drain_queue():
            break
        c.close()
        assert dev.records == [R1, R2]


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
