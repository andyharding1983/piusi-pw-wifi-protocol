#!/usr/bin/env python3
"""
piusi_logger: polls a PIUSI dispenser on an interval and stores every
uplift record in MySQL. Meant to run as a systemd service (see
piusi-logger.service).

Reads are destructive (see docs/PROTOCOL.md), so each record passes through
three durable stages, and each stage is on disk before the next one starts:

  1. raw wire log  -- every byte, fsync'd before decoding (piusi_client.RawLog)
  2. spool file    -- one JSON file per record, fsync'd, written as soon as
                      the frame is received
  3. MySQL         -- inserted from the spool; the spool file is deleted only
                      after the INSERT commits

If MySQL is unreachable, records wait in the spool and are retried on every
cycle. Inserts are keyed on a per-record capture_id, so a retry can't
duplicate a row.

Usage:
    piusi_logger.py --config /etc/piusi-logger/config.ini            # run forever
    piusi_logger.py --config ... --check-db     # test MySQL login + table, no bowser contact
    piusi_logger.py --config ... --flush-only   # push spooled records to MySQL, no bowser contact
    piusi_logger.py --config ... --once         # one polling cycle (DESTRUCTIVE)
"""

from __future__ import annotations

import argparse
import configparser
import datetime
import json
import logging
import os
import re
import signal
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import piusi_client as pc  # noqa: E402

log = logging.getLogger("piusi-logger")

COLUMNS = [
    "capture_id", "received_at_utc", "unit_address",
    "uplift_at", "person", "key_code", "litres",
    "unknown_hex", "unknown_date_byte", "layout", "checksum_matches", "parse_error",
    "raw_hex",
]

# Late replies: how long to listen after the final (unanswered) C before
# disconnecting. Anything arriving after close() would be lost.
LATE_REPLY_WAIT = 3.0


def frame_to_row(frame: pc.Frame, unit_address: str) -> dict:
    """Decode a '+' frame into a table row. Never raises: a record that
    can't be decoded becomes a row with parse_error set and raw_hex kept."""
    row = dict.fromkeys(COLUMNS)
    row.update(
        capture_id=str(uuid.uuid4()),
        received_at_utc=datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        unit_address=unit_address,
        checksum_matches=frame.checksum_matches,
        raw_hex=frame.params.hex(),
    )
    try:
        rec = pc.parse_uplift_record(frame.params)
    except ValueError as e:
        row["parse_error"] = str(e)[:255]
        return row
    ts = rec.timestamp
    row.update(
        uplift_at=ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None,
        person=rec.person,
        key_code=rec.key,
        litres=f"{rec.litres:.2f}",
        unknown_hex=rec.unknown_bytes.hex(),
        unknown_date_byte=rec.unknown_date_byte,
        layout=rec.layout,
    )
    if ts is None:
        row["parse_error"] = "date/time fields are BCD but not a valid timestamp"
    if frame.stuffing_anomaly:
        row["parse_error"] = ((row["parse_error"] or "") + " [DLE stuffing anomaly]").strip()
    return row


class Spool:
    """One JSON file per record, written atomically and fsync'd."""

    def __init__(self, directory: str | os.PathLike):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _fsync_dir(self) -> None:
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, row: dict) -> Path:
        name = f"{row['received_at_utc'].replace(' ', 'T').replace(':', '')}-{row['capture_id']}.json"
        path = self.dir / name
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(row, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        self._fsync_dir()
        return path

    def pending(self) -> list[Path]:
        return sorted(self.dir.glob("*.json"))

    @staticmethod
    def load(path: Path) -> dict:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def remove(self, path: Path) -> None:
        path.unlink()
        self._fsync_dir()


class MySQLSink:
    def __init__(self, cfg: configparser.SectionProxy):
        import mysql.connector  # imported here so --help works without it

        self._mysql = mysql.connector
        self._params = dict(
            host=cfg.get("host", "localhost"),
            port=cfg.getint("port", 3306),
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            connection_timeout=10,
            autocommit=False,
        )
        self.table = cfg.get("table", "fuel_uplifts")
        if not re.fullmatch(r"[A-Za-z0-9_]+", self.table):
            raise ValueError(f"invalid table name: {self.table!r}")
        cols = ", ".join(f"`{c}`" for c in COLUMNS)
        marks = ", ".join(["%s"] * len(COLUMNS))
        # Idempotent: re-inserting a capture_id that already committed is a no-op.
        self._sql = (
            f"INSERT INTO `{self.table}` ({cols}) VALUES ({marks}) "
            f"ON DUPLICATE KEY UPDATE `capture_id` = `capture_id`"
        )
        self._conn = None

    def _connection(self):
        if self._conn is None or not self._conn.is_connected():
            self._conn = self._mysql.connect(**self._params)
        return self._conn

    def insert(self, row: dict) -> None:
        conn = self._connection()
        cur = conn.cursor()
        try:
            cur.execute(self._sql, [row[c] for c in COLUMNS])
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            self._conn = None  # force a fresh connection next time
            raise
        finally:
            cur.close()

    def check(self) -> str:
        conn = self._connection()
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM `{self.table}`")
        (count,) = cur.fetchone()
        cur.execute(f"SHOW COLUMNS FROM `{self.table}`")
        present = {r[0] for r in cur.fetchall()}
        cur.close()
        missing = [c for c in COLUMNS if c not in present]
        if missing:
            raise RuntimeError(f"table {self.table} is missing columns: {missing}")
        return f"connected; table {self.table} has {count} rows and all expected columns"


def flush_spool(spool: Spool, sink: MySQLSink) -> int:
    """Insert spooled records oldest-first; stops at the first DB error."""
    done = 0
    for path in spool.pending():
        row = spool.load(path)
        try:
            sink.insert(row)
        except Exception as e:
            remaining = len(spool.pending())
            log.warning("MySQL insert failed (%s); %d record(s) left in spool for retry", e, remaining)
            break
        spool.remove(path)
        done += 1
    return done


class Stopping:
    """SIGTERM/SIGINT set a flag rather than interrupting mid-record."""

    def __init__(self):
        self.requested = False
        signal.signal(signal.SIGTERM, self._handle)
        signal.signal(signal.SIGINT, self._handle)

    def _handle(self, signum, _frame):
        log.info("received signal %d; finishing current step then stopping", signum)
        self.requested = True


def poll_once(cfg: configparser.ConfigParser, spool: Spool, stop: Stopping) -> int:
    """Connect, drain every queued record into the spool, disconnect."""
    b = cfg["bowser"]
    unit = b["unit_address"]
    log_dir = Path(cfg["service"].get("log_dir", "/var/lib/piusi-logger/raw"))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    client = pc.PiusiClient(
        host=b["host"],
        port=b.getint("port", pc.DEFAULT_PORT),
        unit_address=unit,
        raw_log_path=log_dir / f"piusi-raw-{stamp}.jsonl",
    )
    got = 0
    try:
        client.connect()
        if not client.handshake():
            log.warning("handshake not acknowledged; skipping this cycle")
            return 0
        empty_in_a_row = 0
        while empty_in_a_row < 2 and not stop.requested:
            frame = client.query_next_frame()
            if frame is None:
                empty_in_a_row += 1
                continue
            empty_in_a_row = 0
            spool.write(frame_to_row(frame, unit))
            got += 1
        for frame in client.collect_late_frames(LATE_REPLY_WAIT):
            log.warning("late record collected before disconnect")
            spool.write(frame_to_row(frame, unit))
            got += 1
    finally:
        client.close()
    return got


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="/etc/piusi-logger/config.ini")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="one polling cycle, then exit (DESTRUCTIVE)")
    mode.add_argument("--flush-only", action="store_true", help="push spooled records to MySQL; no bowser contact")
    mode.add_argument("--check-db", action="store_true", help="test MySQL login and table; no bowser contact")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = configparser.ConfigParser()
    if not cfg.read(args.config):
        log.error("can't read config %s", args.config)
        return 2

    sink = MySQLSink(cfg["mysql"])
    if args.check_db:
        log.info(sink.check())
        return 0

    spool = Spool(cfg["service"].get("spool_dir", "/var/lib/piusi-logger/spool"))
    if args.flush_only:
        n = flush_spool(spool, sink)
        log.info("flushed %d record(s); %d still spooled", n, len(spool.pending()))
        return 0 if not spool.pending() else 1

    stop = Stopping()
    interval = cfg["service"].getfloat("poll_interval", 60)
    log.info("starting: bowser %s, poll every %ss", cfg["bowser"]["host"], interval)
    while not stop.requested:
        started = time.time()
        try:
            n = poll_once(cfg, spool, stop)
            if n:
                log.info("received %d record(s)", n)
        except ConnectionError as e:
            log.warning("%s", e)
        except Exception:
            log.exception("polling cycle failed")
        n = flush_spool(spool, sink)
        if n:
            log.info("stored %d record(s) in MySQL", n)
        if args.once:
            break
        while not stop.requested and time.time() - started < interval:
            time.sleep(0.5)
    pending = len(spool.pending())
    if pending:
        log.warning("%d record(s) still in spool %s; they will be retried on next start", pending, spool.dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
