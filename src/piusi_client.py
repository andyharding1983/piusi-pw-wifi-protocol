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
"""

from __future__ import annotations

import dataclasses
import datetime
import socket
import time


DEFAULT_PORT = 12345
MIN_REQUEST_GAP = 1.2  # seconds -- see docs/PROTOCOL.md "Connection behaviour"

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


class PiusiClient:
    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        unit_address: str = "123456",
        connect_timeout: float = 30.0,
        per_attempt_timeout: float = 0.6,
        recv_timeout: float = 2.0,
    ):
        self.host = host
        self.port = port
        self.unit_address = unit_address
        self.connect_timeout = connect_timeout
        self.per_attempt_timeout = per_attempt_timeout
        self.recv_timeout = recv_timeout
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
            self._sock.close()
            self._sock = None

    def _pace(self) -> None:
        elapsed = time.time() - self._last_send_time
        if elapsed < MIN_REQUEST_GAP:
            time.sleep(MIN_REQUEST_GAP - elapsed)

    def _send_and_recv(self, command: bytes, params: bytes = b"") -> bytes | None:
        """Returns raw response bytes, or None on timeout (empty queue / dropped request)."""
        if self._sock is None:
            raise RuntimeError("not connected -- call connect() first")
        self._pace()
        frame = build_frame(self.unit_address, command, params)
        self._sock.sendall(frame)
        self._last_send_time = time.time()
        try:
            return self._sock.recv(256)
        except socket.timeout:
            return None

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
