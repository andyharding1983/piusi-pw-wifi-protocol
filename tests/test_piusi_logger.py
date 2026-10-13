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
from test_piusi_client import FakeBowser, R1, R2, _build_synthetic_record  # noqa: E402


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
    assert row["uplift_at"] == "2026-10-15 09:30:01"
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


def _cfg(dev, tmp):
    cfg = configparser.ConfigParser()
    cfg.read_dict({
        "bowser": {"host": "127.0.0.1", "port": str(dev.port), "unit_address": dev.unit},
        "service": {"log_dir": f"{tmp}/raw", "spool_dir": f"{tmp}/spool"},
    })
    return cfg


def _spooled(spool):
    return [pl.Spool.load(p) for p in spool.pending()]


def test_poll_once_stores_then_confirms_each_record():
    with FakeBowser([R1, R2]) as dev, tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(f"{tmp}/spool")
        assert pl.poll_once(_cfg(dev, tmp), spool, NoStop()) == 2
        P, C, D = pc.CMD_POLL, pc.CMD_CONFIRM, pc.CMD_HANDSHAKE
        assert dev.received == [D, P, C, P, C, P]
        assert dev.records == []
        assert [r["person"] for r in _spooled(spool)] == ["ONE", "TWO"]
        assert list(Path(f"{tmp}/raw").glob("piusi-raw-*.jsonl"))


def test_lost_confirm_resend_is_not_stored_twice():
    # The first C never reaches the device, so it re-sends R1. That must be
    # recognised and confirmed, not stored as a second uplift.
    with FakeBowser([R1, R2], ignore_confirms=1) as dev, tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(f"{tmp}/spool")
        assert pl.poll_once(_cfg(dev, tmp), spool, NoStop()) == 2
        assert dev.records == []
        assert [r["person"] for r in _spooled(spool)] == ["ONE", "TWO"]


def test_resend_recognised_across_cycles():
    # Connection drops after the C is sent but before the device acts on it;
    # the next cycle gets R1 again.
    with FakeBowser([R1], ignore_confirms=1) as dev, tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(f"{tmp}/spool")
        cfg = _cfg(dev, tmp)
        dev.records.append(R2)
        dev.close_after = 3  # D, P, C -> then drop
        assert pl.poll_once(cfg, spool, NoStop()) == 1
        dev.close_after = None
        assert pl.poll_once(cfg, spool, NoStop()) == 1  # R1 recognised, R2 stored
        assert [r["person"] for r in _spooled(spool)] == ["ONE", "TWO"]
        assert dev.records == []


def test_no_reply_stores_nothing_and_deletes_nothing():
    with FakeBowser([R1], ignore_polls=5) as dev, tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(f"{tmp}/spool")
        assert pl.poll_once(_cfg(dev, tmp), spool, NoStop()) == 0
        assert pc.CMD_CONFIRM not in dev.received
        assert dev.records == [R1]
        assert spool.pending() == []


def test_undecodable_record_still_stored_and_confirmed():
    bad = b"\xaa" * 32
    with FakeBowser([bad]) as dev, tempfile.TemporaryDirectory() as tmp:
        spool = pl.Spool(f"{tmp}/spool")
        assert pl.poll_once(_cfg(dev, tmp), spool, NoStop()) == 1
        (row,) = _spooled(spool)
        assert row["parse_error"] and row["raw_hex"] == bad.hex()
        assert dev.records == []


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
