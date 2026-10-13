"""
Client for the PIUSI PW-WiFi / PW-LAN RS485 bridge protocol.

Reverse-engineered, unofficial, not affiliated with PIUSI S.p.A.
See docs/PROTOCOL.md for the full write-up of the protocol and the
operational quirks (flaky TCP accept, required request pacing, and the
destructive-read behaviour of the C command) that this module works around.

Usage:
    from piusi_client import PiusiClient

    client = PiusiClient(host="192.168.1.101", port=12345, unit_address="123456")
    client.connect()       # retries internally, raises if it can't get in
    client.handshake()     # sends D, expects A

    for record in client.drain_queue():
        print(record)      # UpliftRecord(date=..., time=..., person=..., key=..., litres=...)

Every byte sent and received is appended to a raw capture log (see RawLog)
and fsync'd *before* it is parsed. Because C is a destructive read, this log
is the only way to recover a record if parsing fails or is later found to be
wrong. The log contains real customer data -- keep it out of version control.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import socket
import time
from pathlib import Path


DEFAULT_PORT = 12345
MIN_REQUEST_GAP = 1.2  # seconds -- see docs/PROTOCOL.md "Connection behaviour"
DEFAULT_LOG_DIR = Path("~/piusi-logs").expanduser()

DLE_STX = b"\x10\x02"
DLE_ETX = b"\x10\x03"

CMD_HANDSHAKE = b"D"
CMD_HANDSHAKE_ACK = b"A"
CMD_POLL = b"P"
CMD_POLL_ACK = b"0"
CMD_QUERY = b"C"
CMD_RECORD = b"+"

HANDSHAKE_PARAMS = bytes.fromhex("000601000206010402040004")


def checksum(payload: bytes) -> int:
    """XOR of every byte between STX and ETX (address + command + params)."""
    value = 0
    for b in payload:
        value ^= b
    return value


def build_frame(unit_address: str, command: bytes, params: bytes = b"") -> bytes:
    payload = unit_address.encode("ascii") + command + params
    frame = (
        b"\xff\xff\xff\xff\xff"
        + DLE_STX
        + payload
        + DLE_ETX
        + bytes([checksum(payload)])
        + b"\xff"
    )
    return frame


def parse_frame(raw: bytes) -> tuple[str, bytes, bytes] | None:
    """Returns (unit_address, command, params) or None if not a recognisable frame."""
    i = 0
    while i < len(raw) and raw[i] == 0xFF:
        i += 1
    body = raw[i:]
    if len(body) < 2 or body[0:2] != DLE_STX:
        return None
    body = body[2:]
    idx = body.find(DLE_ETX)
    if idx == -1:
        return None
    payload = body[:idx]
    if len(payload) < 7:
        return None
    unit_address = payload[:6].decode("ascii", errors="replace")
    command = payload[6:7]
    params = payload[7:]
    return unit_address, command, params


def _bcd_byte_to_int(b: int) -> int:
    return (b >> 4) * 10 + (b & 0x0F)


@dataclasses.dataclass
class UpliftRecord:
    raw: bytes
    day: int
    month: int
    year: int  # 2-digit, as transmitted
    hour: int
    minute: int
    unknown_date_byte: int
    person: str
    key: str
    litres: float

    @property
    def timestamp(self) -> datetime.datetime | None:
        try:
            return datetime.datetime(2000 + self.year, self.month, self.day, self.hour, self.minute)
        except ValueError:
            return None  # one of the still-unconfirmed byte positions didn't decode cleanly


def parse_uplift_record(params: bytes) -> UpliftRecord:
    """Parse the 33-byte payload of a '+' response. See docs/PROTOCOL.md."""
    if len(params) < 32:
        raise ValueError(f"record too short: {len(params)} bytes, expected >=32")

    day = _bcd_byte_to_int(params[0])
    month = _bcd_byte_to_int(params[1])
    unknown_date_byte = params[2]
    year = _bcd_byte_to_int(params[3])
    hour = _bcd_byte_to_int(params[4])
    minute = _bcd_byte_to_int(params[5])

    person = params[10:20].decode("ascii", errors="replace").rstrip()
    key = params[20:30].decode("ascii", errors="replace").rstrip()

    qty_hi, qty_lo = params[31], params[32]
    qty_raw = _bcd_byte_to_int(qty_hi) * 100 + _bcd_byte_to_int(qty_lo)
    litres = qty_raw / 100.0

    return UpliftRecord(
        raw=params,
        day=day,
        month=month,
        year=year,
        hour=hour,
        minute=minute,
        unknown_date_byte=unknown_date_byte,
        person=person,
        key=key,
        litres=litres,
    )


class RawLog:
    """
    Append-only JSON-lines log of every byte on the wire, one event per line:

        {"ts": "<UTC ISO-8601>", "dir": "tx"|"rx"|"event", "hex": "...", "note": "..."}

    Each line is flushed and fsync'd before write() returns, so a record is
    on disk before anything tries to parse it. Use read_raw_log() to replay.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="ascii")

    def write(self, direction: str, data: bytes = b"", note: str = "") -> None:
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dir": direction,
            "hex": data.hex(),
        }
        if note:
            entry["note"] = note
        self._fh.write(json.dumps(entry) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()


def default_log_path() -> Path:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    return DEFAULT_LOG_DIR / f"piusi-raw-{stamp}.jsonl"


def read_raw_log(path: str | os.PathLike):
    """Yields (timestamp, direction, bytes, note) for each line of a RawLog file."""
    with open(Path(path).expanduser(), encoding="ascii") as fh:
        for line in fh:
            if not line.strip():
                continue
            entry = json.loads(line)
            ts = datetime.datetime.fromisoformat(entry["ts"])
            yield ts, entry["dir"], bytes.fromhex(entry["hex"]), entry.get("note", "")


class PiusiClient:
    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        unit_address: str = "123456",
        connect_timeout: float = 30.0,
        per_attempt_timeout: float = 0.6,
        recv_timeout: float = 2.0,
        raw_log_path: str | os.PathLike | None = None,
    ):
        self.host = host
        self.port = port
        self.unit_address = unit_address
        self.connect_timeout = connect_timeout
        self.per_attempt_timeout = per_attempt_timeout
        self.recv_timeout = recv_timeout
        # Not optional: there is deliberately no way to talk to the device
        # without logging, since reads are destructive. None = default path.
        self.raw_log = RawLog(raw_log_path if raw_log_path is not None else default_log_path())
        self._sock: socket.socket | None = None
        self._last_send_time = 0.0

    def connect(self) -> None:
        """Retry loop -- the converter's TCP accept is flaky by design, see docs/PROTOCOL.md."""
        deadline = time.time() + self.connect_timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.per_attempt_timeout)
            try:
                sock.connect((self.host, self.port))
                sock.settimeout(self.recv_timeout)
                self._sock = sock
                self._last_send_time = 0.0
                self.raw_log.write("event", note=f"connected {self.host}:{self.port}")
                return
            except OSError as e:
                last_error = e
                sock.close()
                time.sleep(0.3)
        raise ConnectionError(
            f"could not connect to {self.host}:{self.port} within {self.connect_timeout}s"
        ) from last_error

    def close(self) -> None:
        if self._sock is not None:
            # Anything still in flight (e.g. a reply that arrived after its
            # request timed out) may be a record the device has already
            # deleted -- log it before the socket goes away.
            self._drain_late_bytes(note="late, at close")
            self._sock.close()
            self._sock = None
            self.raw_log.write("event", note="closed")
        self.raw_log.close()

    def _pace(self) -> None:
        elapsed = time.time() - self._last_send_time
        if elapsed < MIN_REQUEST_GAP:
            time.sleep(MIN_REQUEST_GAP - elapsed)

    def _recv_logged(self, timeout: float, note: str = "") -> bytes:
        """One recv(), logged to disk before returning. b'' on timeout."""
        assert self._sock is not None
        self._sock.settimeout(timeout)
        try:
            chunk = self._sock.recv(4096)
        except socket.timeout:
            return b""
        if chunk:
            self.raw_log.write("rx", chunk, note=note)
        else:
            self.raw_log.write("event", note="peer closed connection")
        return chunk

    def _drain_late_bytes(self, note: str) -> bytes:
        data = b""
        while chunk := self._recv_logged(0.05, note=note):
            data += chunk
        return data

    def _send_and_recv(self, command: bytes, params: bytes = b"") -> bytes | None:
        """Returns raw response bytes, or None on timeout (empty queue / dropped request)."""
        if self._sock is None:
            raise RuntimeError("not connected -- call connect() first")
        self._pace()
        # Late replies to an earlier request get logged here instead of being
        # mistaken for the reply to this one.
        self._drain_late_bytes(note="late, before send")
        frame = build_frame(self.unit_address, command, params)
        self.raw_log.write("tx", frame)
        self._sock.sendall(frame)
        self._last_send_time = time.time()
        resp = self._recv_logged(self.recv_timeout)
        if not resp:
            self.raw_log.write("event", note=f"no reply to {command.decode('ascii', 'replace')}")
            return None
        # A frame can be split across TCP segments; collect the rest.
        resp += self._drain_late_bytes(note="continuation")
        return resp

    def handshake(self) -> bool:
        resp = self._send_and_recv(CMD_HANDSHAKE, HANDSHAKE_PARAMS)
        if resp is None:
            return False
        parsed = parse_frame(resp)
        return parsed is not None and parsed[1] == CMD_HANDSHAKE_ACK

    def poll(self) -> bool:
        """Heartbeat -- not required for data extraction, included for completeness."""
        resp = self._send_and_recv(CMD_POLL)
        if resp is None:
            return False
        parsed = parse_frame(resp)
        return parsed is not None and parsed[1] == CMD_POLL_ACK

    def query_next_record(self) -> UpliftRecord | None:
        """
        Sends C. Returns the next queued record, or None if the queue is
        currently empty (request timed out with no response).

        WARNING: a successful response here appears to permanently remove
        the record from the device's queue (destructive read). See
        docs/PROTOCOL.md.
        """
        resp = self._send_and_recv(CMD_QUERY)
        if resp is None:
            return None
        parsed = parse_frame(resp)
        if parsed is None or parsed[1] != CMD_RECORD:
            return None
        _, _, params = parsed
        return parse_uplift_record(params)

    def drain_queue(self, max_empty_in_a_row: int = 2):
        """
        Generator: yields UpliftRecord objects until the queue appears
        empty (max_empty_in_a_row consecutive timeouts).
        """
        empty_count = 0
        while empty_count < max_empty_in_a_row:
            record = self.query_next_record()
            if record is None:
                empty_count += 1
                continue
            empty_count = 0
            yield record
