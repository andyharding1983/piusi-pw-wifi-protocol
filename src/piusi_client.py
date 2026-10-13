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
    """XOR of address + command + params, computed over the *unstuffed* bytes.

    Which variant the device uses is not yet confirmed for frames that
    contain stuffed bytes -- see Frame.checksum_matches.
    """
    value = 0
    for b in payload:
        value ^= b
    return value


def dle_stuff(data: bytes) -> bytes:
    """Double every 0x10 (DLE) so it can't be mistaken for a frame delimiter."""
    return data.replace(b"\x10", b"\x10\x10")


def build_frame(unit_address: str, command: bytes, params: bytes = b"") -> bytes:
    payload = unit_address.encode("ascii") + command + params
    frame = (
        b"\xff\xff\xff\xff\xff"
        + DLE_STX
        + dle_stuff(payload)
        + DLE_ETX
        + dle_stuff(bytes([checksum(payload)]))
        + b"\xff"
    )
    return frame


@dataclasses.dataclass
class Frame:
    unit_address: str
    command: bytes
    params: bytes  # DLE stuffing already removed
    checksum: int  # as received
    # "unstuffed", "stuffed", "both" (identical when the number of stuffed
    # bytes is even), or None if neither matches. Recorded rather than
    # enforced: rejecting a frame would throw away a destructively-read record.
    checksum_matches: str | None
    stuffing_anomaly: bool = False  # saw 0x10 followed by an unexpected byte


class FrameDecoder:
    """
    Incremental decoder for the byte stream from the bridge. Feed it chunks
    as they arrive (a frame may be split across TCP segments, or several
    frames may share one); it returns every complete frame found.

    Inside a frame, 0x10 0x10 is a literal 0x10, 0x10 0x03 ends the frame,
    and 0x10 0x02 aborts the current frame and starts a new one.
    """

    def __init__(self):
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        self._buf += data
        frames = []
        while True:
            start = self._buf.find(DLE_STX)
            if start == -1:
                # Keep a trailing 0x10 in case it's the first half of an STX.
                del self._buf[: max(0, len(self._buf) - 1)]
                return frames
            result = self._decode_from(start + 2)
            if result is None:
                del self._buf[:start]  # incomplete -- wait for more bytes
                return frames
            frame, consumed_to = result
            del self._buf[:consumed_to]
            if frame is not None:
                frames.append(frame)

    def _decode_from(self, i: int):
        """Returns (Frame or None, index after frame), or None if incomplete."""
        buf = self._buf
        payload = bytearray()
        stuffed = bytearray()  # the payload exactly as it appeared on the wire
        anomaly = False
        while True:
            if i >= len(buf):
                return None
            b = buf[i]
            if b != 0x10:
                payload.append(b)
                stuffed.append(b)
                i += 1
                continue
            if i + 1 >= len(buf):
                return None
            nxt = buf[i + 1]
            if nxt == 0x10:
                payload.append(0x10)
                stuffed += b"\x10\x10"
                i += 2
            elif nxt == 0x03:
                i += 2
                break
            elif nxt == 0x02:
                return None, i  # restart at the new STX
            else:
                anomaly = True
                payload.append(0x10)
                stuffed.append(0x10)
                i += 1

        # Checksum byte, itself possibly stuffed.
        if i >= len(buf):
            return None
        cks = buf[i]
        i += 1
        if cks == 0x10:
            if i >= len(buf):
                return None
            if buf[i] == 0x10:
                i += 1

        if len(payload) < 7:
            return None, i
        unstuffed_ok = checksum(bytes(payload)) == cks
        stuffed_ok = checksum(bytes(stuffed)) == cks
        matches = (
            "both" if unstuffed_ok and stuffed_ok
            else "unstuffed" if unstuffed_ok
            else "stuffed" if stuffed_ok
            else None
        )
        frame = Frame(
            unit_address=bytes(payload[:6]).decode("ascii", errors="replace"),
            command=bytes(payload[6:7]),
            params=bytes(payload[7:]),
            checksum=cks,
            checksum_matches=matches,
            stuffing_anomaly=anomaly,
        )
        return frame, i


def parse_frame(raw: bytes) -> tuple[str, bytes, bytes] | None:
    """Returns (unit_address, command, params) of the first frame in raw, or None."""
    frames = FrameDecoder().feed(raw)
    if not frames:
        return None
    f = frames[0]
    return f.unit_address, f.command, f.params


def _bcd(data: bytes, field: str) -> int:
    """Decode packed BCD (two decimal digits per byte), rejecting non-decimal nibbles."""
    value = 0
    for b in data:
        hi, lo = b >> 4, b & 0x0F
        if hi > 9 or lo > 9:
            raise ValueError(f"{field}: invalid BCD byte 0x{b:02x} in {data.hex()}")
        value = value * 100 + hi * 10 + lo
    return value


@dataclasses.dataclass
class UpliftRecord:
    raw: bytes  # the '+' params, DLE stuffing removed
    day: int
    month: int
    year: int  # 2-digit, as transmitted
    hour: int
    minute: int
    unknown_date_byte: int | None  # only present in the legacy 33-byte layout
    unknown_bytes: bytes  # 4 undecoded bytes between time and person
    person: str
    key: str
    litres: float
    layout: str  # "dle" (32 bytes) or "legacy" (33 bytes)

    @property
    def timestamp(self) -> datetime.datetime | None:
        try:
            return datetime.datetime(2000 + self.year, self.month, self.day, self.hour, self.minute)
        except ValueError:
            return None


def parse_uplift_record(params: bytes) -> UpliftRecord:
    """
    Parse the payload of a '+' response (stuffing already removed). See
    docs/PROTOCOL.md.

    Expected: 32 bytes -- date [day][month][year], time [hour][minute],
    4 unknown, person (10), key (10), quantity (3 bytes BCD, litres x100).

    A 33-byte payload is the layout originally documented, with an extra
    byte after the month. That byte is believed to have been a DLE-stuffed
    month of 0x10 (October), in which case it can't appear after unstuffing.
    It's still accepted, so that a capture disproving the theory decodes
    rather than gets thrown away.

    Raises ValueError rather than guess. The raw bytes are already in the
    capture log, so a record that can't be decoded is still recoverable.
    """
    if len(params) == 32:
        layout, extra = "dle", None
        body = params
    elif len(params) == 33:
        layout, extra = "legacy", params[2]
        body = params[:2] + params[3:]
    else:
        raise ValueError(f"unexpected record length {len(params)} (expected 32): {params.hex()}")

    return UpliftRecord(
        raw=params,
        day=_bcd(body[0:1], "day"),
        month=_bcd(body[1:2], "month"),
        year=_bcd(body[2:3], "year"),
        hour=_bcd(body[3:4], "hour"),
        minute=_bcd(body[4:5], "minute"),
        unknown_date_byte=extra,
        unknown_bytes=bytes(body[5:9]),
        person=body[9:19].decode("ascii", errors="replace").rstrip(),
        key=body[19:29].decode("ascii", errors="replace").rstrip(),
        litres=_bcd(body[29:32], "quantity") / 100.0,
        layout=layout,
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
        self._decoder = FrameDecoder()
        self._inbox: list[Frame] = []

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
                self._decoder = FrameDecoder()  # discard any half-frame from a previous connection
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
            undelivered = sum(1 for f in self._inbox if f.command == CMD_RECORD)
            if undelivered:
                self.raw_log.write(
                    "event",
                    note=f"{undelivered} record frame(s) received but not returned -- recover from this log",
                )
            self.raw_log.write("event", note="closed")
        self.raw_log.close()

    def _pace(self) -> None:
        elapsed = time.time() - self._last_send_time
        if elapsed < MIN_REQUEST_GAP:
            time.sleep(MIN_REQUEST_GAP - elapsed)

    def _recv_logged(self, timeout: float, note: str = "") -> bytes:
        """One recv(), logged to disk before it is decoded. b'' on timeout/close."""
        assert self._sock is not None
        self._sock.settimeout(timeout)
        try:
            chunk = self._sock.recv(4096)
        except socket.timeout:
            return b""
        except OSError as e:
            self.raw_log.write("event", note=f"recv failed: {e!r}")
            return b""
        if not chunk:
            self.raw_log.write("event", note="peer closed connection")
            return b""
        self.raw_log.write("rx", chunk, note=note)
        self._inbox.extend(self._decoder.feed(chunk))
        return chunk

    def _drain_late_bytes(self, note: str) -> None:
        while self._recv_logged(0.05, note=note):
            pass

    def _take(self, command: bytes) -> Frame | None:
        for i, frame in enumerate(self._inbox):
            if frame.command == command:
                return self._inbox.pop(i)
        return None

    def _send(self, command: bytes, params: bytes = b"") -> None:
        if self._sock is None:
            raise RuntimeError("not connected -- call connect() first")
        self._pace()
        self._drain_late_bytes(note="late, before send")
        # Stale acks would be mistaken for the reply to this request. Record
        # frames are kept: they have already been deleted from the device.
        self._inbox = [f for f in self._inbox if f.command == CMD_RECORD]
        frame = build_frame(self.unit_address, command, params)
        self.raw_log.write("tx", frame)
        self._sock.sendall(frame)
        self._last_send_time = time.time()

    def _await(self, command: bytes) -> Frame | None:
        """Wait up to recv_timeout for a frame with the given command."""
        deadline = time.time() + self.recv_timeout
        while True:
            frame = self._take(command)
            if frame is not None:
                return frame
            remaining = deadline - time.time()
            if remaining <= 0 or not self._recv_logged(remaining):
                frame = self._take(command)
                if frame is None:
                    self.raw_log.write("event", note=f"no {command.decode('ascii', 'replace')} frame received")
                return frame

    def handshake(self) -> bool:
        self._send(CMD_HANDSHAKE, HANDSHAKE_PARAMS)
        return self._await(CMD_HANDSHAKE_ACK) is not None

    def poll(self) -> bool:
        """Heartbeat -- not required for data extraction, included for completeness."""
        self._send(CMD_POLL)
        return self._await(CMD_POLL_ACK) is not None

    def query_next_frame(self) -> Frame | None:
        """
        Returns the next queued '+' frame (undecoded), or None if the queue
        is currently empty (request timed out with no response).

        A record that arrived late (after an earlier request timed out) is
        returned first, without sending another C.

        WARNING: a successful response here appears to permanently remove
        the record from the device's queue (destructive read). See
        docs/PROTOCOL.md.
        """
        if self._sock is None:
            raise RuntimeError("not connected -- call connect() first")
        # Pick up any late reply *before* deciding to send another C --
        # otherwise we'd pop a second record off the device.
        self._pace()
        self._drain_late_bytes(note="late, before send")
        frame = self._take(CMD_RECORD)
        if frame is None:
            self._send(CMD_QUERY)
            frame = self._await(CMD_RECORD)
        return frame

    def collect_late_frames(self, wait: float) -> list[Frame]:
        """
        Listens for `wait` seconds without sending anything, and returns any
        '+' frames that arrive or are already pending. Call before close()
        if the last C might still be answered.
        """
        if self._sock is None:
            raise RuntimeError("not connected -- call connect() first")
        deadline = time.time() + wait
        while (remaining := deadline - time.time()) > 0:
            if not self._recv_logged(remaining, note="late, collected"):
                break
        frames = [f for f in self._inbox if f.command == CMD_RECORD]
        self._inbox = [f for f in self._inbox if f.command != CMD_RECORD]
        return frames

    def query_next_record(self) -> UpliftRecord | None:
        """
        query_next_frame(), decoded. Same destructive-read warning applies.
        Raises ValueError if a record can't be decoded; its raw bytes are in
        the capture log. Use query_next_frame() to handle that yourself.
        """
        frame = self.query_next_frame()
        if frame is None:
            return None
        return parse_uplift_record(frame.params)

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
