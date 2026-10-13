# PIUSI PW-WiFi / PW-LAN RS485 bridge protocol

Reverse-engineered by packet-capturing PIUSI's own "SSM 2.0" / MC-BOX desktop
management software talking to a PW-LAN converter (RS485-to-Ethernet bridge,
also sold as part of the "PW-WiFi" kit). PIUSI does not publish this protocol
anywhere — not in the installation manuals, not in the software manuals, not
on their product pages. Everything below was derived from a live traffic
capture and cross-checked against the official software's own displayed
records, including a known-quantity test dispense.

**Disclaimer:** this is a third-party, unofficial reverse-engineering effort.
It is not affiliated with or endorsed by PIUSI S.p.A. Field names and
interpretations are best-effort based on observed behaviour, not from any
official specification.

## Network layout

```
fuel meter (pulse-counting dispenser console, e.g. "Self Service" FM/MC)
   | RS485, 230400 baud, 7 data bits, no parity, 1 stop bit
   v
PW-LAN converter (RS485 <-> Ethernet/WiFi bridge)
   | TCP
   v
PC running PIUSI's own management software
```

The PW-LAN converter is a thin, mostly transparent bridge. The actual
protocol logic lives in the dispenser console; the converter just relays
bytes between RS485 and TCP.

### Discovered services on the converter

| Port | Protocol | Purpose |
|---|---|---|
| 80 | HTTP | Web config UI. Login `admin` / `piusipass` (PIUSI's own documented default). Tabs: Network, System, RS485 — configuration only, no data. |
| 12345 | TCP | **The actual data channel.** Not discoverable by port-scanning reliably (see Connection behaviour below) — only found by capturing real client traffic. |
| 12350 | UDP broadcast | Device announces itself every ~6s: plaintext `PIUSI_485-ETHERNET MAC=<mac> HOSTNAME=<name> VER=<ver>`. This is what "Detect System" in the official software listens for. |

## Connection behaviour — read this before writing a client

The converter's firmware appears to be single-threaded and has essentially
no slack:

- **TCP accept is flaky.** A bare `connect()` to port 12345 succeeds only
  intermittently (roughly 1-in-4 attempts when the device is otherwise idle).
  When the official software is actively connected, our connection attempts
  — and even the HTTP server — can fail almost entirely, because the
  device's single thread of execution is consumed servicing that one client.
  This is *not* a firewall/IP-allowlist behaviour (confirmed by testing from
  multiple machines on multiple network paths) — it's resource starvation.
  **Always connect with a retry loop** (short per-attempt timeout, retry
  every 0.3–0.5s, budget up to ~30s to get in).

- **No request queueing.** Measured the official software's own request
  cadence from a real capture: 95% of consecutive sends are spaced
  **1.2–1.3 seconds apart**, regardless of command type. This is almost
  certainly empirically tuned by PIUSI to match the round-trip time the
  bridge needs (TCP → RS485 write → dispenser console processes → RS485
  response → TCP relay) before it can accept the next command. Sending
  faster likely gets silently dropped rather than queued.
  **Pace all requests at ≥1.2s apart, strictly request-then-response,
  never pipeline.**

## Frame format

```
[0xFF preamble, 3–5 bytes]
[0x10 0x02 — DLE STX]
[6-byte ASCII unit address, e.g. "123456"]
[1-byte command]
[params, variable length]
[0x10 0x03 — DLE ETX]
[1-byte checksum]
[0xFF trailer, 1–2 bytes]
```

**Checksum** = XOR of every byte from the start of the address through the
end of params (i.e. everything between STX and ETX, inclusive). Verified
against every frame type observed.

The preamble/trailer `0xFF` byte counts vary slightly (3–5 preamble bytes,
1–2 trailer bytes) between frames; they appear to be line-idle padding
rather than meaningful framing, since TCP segments were sometimes seen
coalescing multiple complete frames back-to-back with full 5-byte preambles
between them.

## Commands

| Cmd | ASCII | Direction | Meaning |
|---|---|---|---|
| `0x44` | `D` | client → device | Session handshake. Send once immediately after connecting. Params observed: `00 06 01 00 02 06 01 04 02 04 00 04` (12 bytes, meaning unknown — possibly client capability/version flags). |
| `0x41` | `A` | device → client | Ack to the handshake, no payload. |
| `0x50` | `P` | client → device | Heartbeat/poll. No params. Used by the official software to keep the link alive between data polls; not required for data extraction. |
| `0x30` | `0` | device → client | Ack to `P`, no payload. |
| `0x43` | `C` | client → device | "Pop next record" query. No params. |
| `0x2b` | `+` | device → client | A queued uplift record (see below). **Only sent if the device actually has a record to return** — if the backlog is empty, the device sends nothing and the request times out, rather than replying with an empty/null record. |

Example raw bytes (address anonymized to `123456`; checksums recomputed to match
— these are not a verbatim capture, see src/piusi_client.py for a tested
frame builder/parser):

```
D:  ff ff ff ff ff 10 02 31 32 33 34 35 36 44 00 06 01 00 02 06 01 04 02 04 00 04 10 03 47 ff
P:  ff ff ff ff ff 10 02 31 32 33 34 35 36 50 10 03 57 ff
C:  ff ff ff ff ff 10 02 31 32 33 34 35 36 43 10 03 44 ff
```

## `+` response — uplift record format

33 bytes between the command byte and ETX:

```
offset  size  field
0       4     date, BCD: [day] [month] [?] [year-2digits]
4       2     time, BCD: [hour] [minute]
6       4     unknown (seen as low, non-constant values; possibly a
              sub-second counter or sequence id — not yet decoded)
10      10    "person" field — free text entered by the operator,
              space-padded ASCII (e.g. name, or a generic description)
20      10    "key" field — the registered key/ID, space-padded ASCII.
              At the site this was reverse-engineered on, these are UK
              civil aircraft registrations (G-xxxx format) since it's an
              aviation refuelling site — on a road-fuel site this is
              presumably a vehicle reg or fuel card ID instead.
30      2     quantity, BCD, litres x100 (i.e. divide by 100 for litres)
32      1     pad / unknown, usually 0x00
```

**This is a historical backlog, not a live snapshot.** The device appears
to hold completed-but-uncollected uplifts in a queue and hands them out
oldest-first, one per successful `C` poll. Confirmed by capturing six
records within an 8-second burst of polling whose embedded timestamps
spanned roughly two hours — they were clearly queued, not live.

### Verified against ground truth

- **Quantity scale:** a test dispense recalled as "about 0.4L" produced a
  raw value of `0041`. `0041 / 100 = 0.41L` — confirmed.
- **Date encoding:** a capture session run on 6 Oct 2026 produced date
  bytes `06 10 10 26` → day=06, month=10, year=26. Day/month/year all
  correct in that byte order.
- **All six field-set values (person, key, quantity) in one capture
  session were cross-checked against the official software's own
  displayed records and matched.**

### Open questions

- **Byte index 2 of the date field** (the second `0x10` in `06 10 10 26`)
  is unexplained. It happened to equal the month byte in every record
  captured so far (all from the same day). Need a capture from a
  different month to tell whether it tracks the month (and if so, why
  it's duplicated) or is an unrelated constant.
- **Bytes 6–9** (between the time and the person field) are low,
  non-constant, undecoded. Possibly a sub-second timestamp component or
  an internal sequence/transaction ID.
- **No bulk/report-dump command has been observed.** Everything captured
  so far is one record at a time via `C`. It's possible one exists and
  simply wasn't triggered during the capture window (e.g. a "export
  report" action in the official software) — worth capturing specifically
  for that.

## Destructive read — operational warning

**Successfully receiving a `+` response appears to permanently remove
that record from the device's queue.** If the official PIUSI software
later tries to collect the same record, it will not be there — this
isn't a duplicate-read situation, it's "whoever reads it first gets it."

Implications for any tool built on this protocol:
- Don't poll `C` speculatively against a live, in-use system without the
  operator's explicit knowledge — you may be taking records their
  official accounting software will never see.
- Log every byte received to disk immediately (write, flush, fsync) as
  it arrives, not after a batch — there's no way to re-request a record
  once it's gone.
