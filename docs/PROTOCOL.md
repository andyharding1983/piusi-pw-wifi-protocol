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
end of params (i.e. everything after STX and before ETX). Verified against
every frame type observed.

### DLE byte-stuffing

Because `0x10` (DLE) introduces the STX/ETX delimiters, a literal `0x10`
inside the address/command/params is sent doubled as `10 10`, in the usual
DLE-framing convention. Evidence: every `+` record in the capture was from
October, where the month byte is BCD `0x10`, and showed what was first read
as an unexplained duplicate `0x10` (`06 10 10 26`). With stuffing removed,
every record is exactly 32 bytes, and its checksum matches **only** when
computed over the un-stuffed bytes.

Consequences for a client:
- A receiver must un-stuff (`10 10` → `10`) and must **not** simply search
  for the first `10 03`: e.g. October at 10:03 puts `10 10 10 10 03` inside
  the data.
- `0x10 0x02` inside a frame means a new frame has started.
- The checksum is the XOR of the **un-stuffed** bytes. The checksum byte may
  itself be `0x10`, presumably also stuffed (not yet seen).

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
| `0x50` | `P` | client → device | **Poll for the oldest pending record.** No params. |
| `0x2b` | `+` | device → client | Reply to `P`: the oldest pending uplift record (see below). The record is **not** deleted yet. |
| `0x30` | `0` | device → client | Reply to `P`: nothing pending. No payload. |
| `0x43` | `C` | client → device | **Confirm** the record just received. No params, **no reply**. The device deletes that record; the next `P` returns the next one. (Possibly *conferma* or *cancella* — PIUSI is Italian.) |

The official software's sequence, from the capture:

```
D → A
P → +   (record 1)      C   (20–170 ms after the +)
P → +   (record 2)      C   (P sent ~1.22 s after the previous C)
...
P → 0   (nothing left)
P → 0   (heartbeat, every ~1.2 s while connected)
```

**An earlier version of this document had `P` and `C` the wrong way
round** (`C` as "pop next record", `P` as an optional heartbeat). That was
a misreading of the capture: every `+` is the reply to a `P`, and `C` is
sent *after* it. A client built on the old reading sends `C` with no
record pending, which gets no reply — and may delete a record nobody has
seen (see below).

Example raw bytes (address anonymized to `123456`; checksums recomputed to match
— these are not a verbatim capture, see src/piusi_client.py for a tested
frame builder/parser):

```
D:  ff ff ff ff ff 10 02 31 32 33 34 35 36 44 00 06 01 00 02 06 01 04 02 04 00 04 10 03 47 ff
P:  ff ff ff ff ff 10 02 31 32 33 34 35 36 50 10 03 57 ff
C:  ff ff ff ff ff 10 02 31 32 33 34 35 36 43 10 03 44 ff
```

## `+` response — uplift record format

32 bytes between the command byte and ETX, **after** removing DLE
stuffing (see above):

```
offset  size  field
0       3     date, BCD: [day] [month] [year-2digits]
3       2     time, BCD: [hour] [minute]
5       1     seconds, plain binary (NOT BCD) -- inferred: every value
              seen is 0-59 (e.g. 0x2e = 46, which isn't valid BCD)
6       3     unknown, all 0x00 so far
9       10    "person" field — free text entered by the operator,
              space-padded ASCII (e.g. name, or a generic description)
19      10    "key" field — the registered key/ID, space-padded ASCII.
              At the site this was reverse-engineered on, these are UK
              civil aircraft registrations (G-xxxx format) since it's an
              aviation refuelling site — on a road-fuel site this is
              presumably a vehicle reg or fuel card ID instead.
29      3     quantity, BCD, litres x100 (i.e. divide by 100 for litres)
```

This layout was originally documented as 33 bytes with a 4-byte date
`[day] [month] [?] [year]`, a 2-byte quantity, and a trailing "pad, usually
`0x00`" byte. Every captured record was from October (month = `0x10`), so
the extra date byte is explained by stuffing, and the remaining offsets
match the table above. The "pad" byte is then the **high byte of a 3-byte
quantity**: zero for any uplift under 100 L, which every captured
record was. The old 2-byte reading would have shown a 150.00 L uplift
(`01 50 00`) as 50.00 L.

The client still accepts a 33-byte un-stuffed record using the old layout
(`UpliftRecord.layout == "legacy"`), so a capture that disproves this
decodes instead of being lost.

**This is a historical backlog, not a live snapshot.** The device appears
to hold completed-but-uncollected uplifts in a queue and hands them out
oldest-first, one per `P`, each removed by the following `C`. Confirmed by capturing six
records within an 8-second burst of polling whose embedded timestamps
spanned roughly two hours — they were clearly queued, not live.

### Verified against ground truth

- **Quantity scale:** a test dispense recalled as "about 0.4L" produced a
  raw value of `0041`. `0041 / 100 = 0.41L` — confirmed.
- **Date encoding:** a capture session run on 6 Oct 2026 produced date
  bytes `06 10 10 26` on the wire → day=06, month=10 (stuffed as `10 10`),
  year=26. Day/month/year all correct in that byte order.
- **All six field-set values (person, key, quantity) in one capture
  session were cross-checked against the official software's own
  displayed records and matched.**

### Open questions

- **Non-October months**: stuffing is consistent with everything seen, but
  every record so far was from October. A record from another month should
  have a 3-byte date on the wire with no duplicate.
- **3-byte quantity**: confirm with an uplift of 100 L or more; its first
  quantity byte should be non-zero.
- **Seconds byte** (offset 5) is inferred from values all being 0-59.
  Bytes 6-8 have only been seen as `00`.
- **`P` without `C`**: expected to return the same record again (the
  device shouldn't delete until confirmed), but not yet observed.
- **`C` with nothing just sent** (a "blind" `C`): unknown whether the
  device ignores it or deletes its oldest record unseen. Never do this.
- **Date/time setting**: the official software may set the device clock
  (e.g. periodically, or via a menu action). Not seen in the capture.
- **No bulk/report-dump command has been observed.** Everything captured
  so far is one record at a time via `P`/`C`.

## Destructive confirm — operational warning

**`C` deletes the record from the device.** If the official PIUSI software
later tries to collect the same record, it won't be there: whoever
confirms it first gets it.

Implications for any tool built on this protocol:
- Only send `C` immediately after receiving a `+`, and only once that
  record is durably stored. Never send `C` speculatively or as a "query".
- Log every byte received to disk immediately (write, flush, fsync) as it
  arrives, before decoding.
- Expect the bridge to drop connections and miss replies. A missing reply
  to `P` is safe (nothing is deleted without `C`). A `C` that doesn't reach
  the device means the same record comes back on the next `P` — recognise
  it (its bytes include the time to the second) rather than storing it twice.
- Don't run two clients against one device: the bridge serves one at a
  time, and whichever confirms a record takes it.
