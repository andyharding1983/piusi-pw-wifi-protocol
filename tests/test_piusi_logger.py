"""
Tests for service/piusi_logger.py. No real bowser or MySQL: the bowser is a
local fake TCP server and MySQL is a stand-in sink. All fixtures synthetic.
"""

import configparser
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "service"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import piusi_client as pc  # noqa: E402
import piusi_logger as pl  # noqa: E402
from test_piusi_client import _build_synthetic_record, _fake_device  # noqa: E402


class FakeSink:
    def __init__(self, fail_after=None):
        self.rows = {}
        self.fail_after = fail_after

    def insert(self, row):
        if self.fail_after is not None and len(self.rows) >= self.fail_after:
            raise ConnectionError("db down")
        self.rows[row["capture_id"]] = row  # idempotent, like ON DUPLICATE KEY


class NoStop:
    requested = False


def _frame(params):
    return pc.FrameDecoder().feed(pc.build_frame("123456", pc.CMD_RECORD, params))[0]


def test_frame_to_row_decoded():
    row = pl.frame_to_row(_frame(_build_synthetic_record(month=10, litres=150.0)), "123456")
    assert set(row) == set(pl.COLUMNS)
    assert row["uplift_at"] == "2026-10-15 09:30:00"
    assert row["key_code"] == "TESTKEY1"
    assert row["litres"] == "150.00"
    assert row["layout"] == "dle"
    assert row["parse_error"] is None
    assert len(row["capture_id"]) == 36


def test_frame_to_row_undecodable_keeps_raw():
    params = b"\xaa" * 32
    row = pl.frame_to_row(_frame(params), "123456")
    assert row["parse_error"]
    assert row["litres"] is None and row["uplift_at"] is None
    assert row["raw_hex"] == params.hex()


def test_spool_survives_db_outage_and_retries():
    with tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(tmp)
        for litres in (1.0, 2.0, 3.0):
            spool.write(pl.frame_to_row(_frame(_build_synthetic_record(litres=litres)), "123456"))
        sink = FakeSink(fail_after=1)
        assert pl.flush_spool(spool, sink) == 1
        assert len(spool.pending()) == 2  # nothing lost while DB is down
        sink.fail_after = None
        assert pl.flush_spool(spool, sink) == 2
        assert spool.pending() == []
        assert sorted(r["litres"] for r in sink.rows.values()) == ["1.00", "2.00", "3.00"]


def test_poll_once_spools_records_including_late_one():
    frame = pc.build_frame("123456", pc.CMD_RECORD, _build_synthetic_record())
    ack = pc.build_frame("123456", pc.CMD_HANDSHAKE_ACK)
    # The fake answers the handshake with an ack and the record together, as
    # if the record reply were delayed past the first C's timeout.
    port, done = _fake_device([ack, frame])
    saved = pc.MIN_REQUEST_GAP, pl.LATE_REPLY_WAIT
    pc.MIN_REQUEST_GAP, pl.LATE_REPLY_WAIT = 0.0, 0.2
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = configparser.ConfigParser()
            cfg.read_dict({
                "bowser": {"host": "127.0.0.1", "port": str(port), "unit_address": "123456"},
                "service": {"log_dir": f"{tmp}/raw", "spool_dir": f"{tmp}/spool"},
            })
            spool = pl.Spool(f"{tmp}/spool")
            n = pl.poll_once(cfg, spool, NoStop())
            done.set()
            assert n == 1
            (path,) = spool.pending()
            assert pl.Spool.load(path)["key_code"] == "TESTKEY1"
            assert list(Path(f"{tmp}/raw").glob("piusi-raw-*.jsonl"))
    finally:
        pc.MIN_REQUEST_GAP, pl.LATE_REPLY_WAIT = saved


if __name__ == "__main__":
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
