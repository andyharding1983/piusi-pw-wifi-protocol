# piusi-pw-wifi-protocol

Unofficial, reverse-engineered client for the PIUSI PW-WiFi / PW-LAN RS485
bridge used by PIUSI fuel dispensers (Self Service FM/MC, Cube MC, MC-BOX,
Ocio, MCO). Lets you pull fuel uplift records (date, time, operator, key/
registration, litres) directly, without PIUSI's own desktop management
software.

**Not affiliated with or endorsed by PIUSI S.p.A.** Built by packet-capturing
their own software and reverse-engineering the protocol, because PIUSI
doesn't publish any technical documentation for it (checked their install
manuals, software manuals, and product pages — nothing). See
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full write-up, including what's
confirmed vs. still unknown.

## Status

Protocol is decoded and working:
- Connect / handshake / poll-for-records all implemented and tested.
- Record format (date, time, operator, key, litres) confirmed against the
  official software's own data on a real site.
- See [`docs/PROTOCOL.md`](docs/PROTOCOL.md#open-questions) for what's still
  unconfirmed (DLE byte-stuffing and the 3-byte quantity field are inferred
  and need confirming; no bulk/report-dump command found yet).

**Read the "Destructive read — operational warning" section in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md#destructive-read--operational-warning)
before polling against a live system.** Successfully reading a record
appears to permanently remove it from the device — if PIUSI's own software
hasn't collected it yet, it never will.

## Usage

```python
from piusi_client import PiusiClient

client = PiusiClient(host="192.168.1.101", unit_address="YOUR_UNIT_ADDRESS")
# unit_address is YOUR device's RS485 address -- there's no shared/default
# value, every site's dispenser has its own. See docs/PROTOCOL.md for how
# to find it (capture traffic from the official software).
client.connect()      # retries internally -- the bridge's TCP accept is flaky
client.handshake()

for record in client.drain_queue():
    print(record.timestamp, record.person, record.key, record.litres)
```

Every byte sent and received is appended to a raw capture log, and fsync'd
to disk *before* anything is parsed. The log defaults to
`~/piusi-logs/piusi-raw-YYYY-MM-DD.jsonl`; pass `raw_log_path=` to change
it. There is deliberately no way to turn it off: reads are destructive,
so if a record fails to parse (or the parser is later found to be wrong)
this log is the only copy. Replay it with `read_raw_log()`. **The log
contains real customer data — keep it out of version control.**

See [`src/piusi_client.py`](src/piusi_client.py) for the full API.

## Tests

```
python3 tests/test_piusi_client.py
```

All test fixtures are synthetic/hand-constructed, not from any real capture.

## Contributing

If you've got a PIUSI PW-WiFi setup and can capture traffic from the
official software, particularly:
- a transaction/report *export* action (we've only ever seen one-record-at-
  a-time polling, never a bulk dump),
- a capture from a month other than October (to confirm the DLE
  byte-stuffing explanation of the old "unexplained date byte"),
- a record for an uplift of 100 L or more (to confirm the 3-byte
  quantity field),

...an issue or PR with the anonymized capture would be very welcome.

## License

MIT — see [`LICENSE`](LICENSE).
