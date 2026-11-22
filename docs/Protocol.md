# Wire Protocol: GAIA v1 + Qualcomm Upgrade over Bluetooth SPP

Everything runs on a single Bluetooth Classic SPP (RFCOMM) connection to the
stock service, SDP class `00001101-0000-1000-8000-00805F9B34FB`. The BTR15
exposes this service in normal Bluetooth mode; the phone that is paired for
audio is not required — a second socket to the same service works while the
device plays music.

## GAIA v1 framing

Every packet, in both directions:

```
FF 01 flags len vendor:u16be cmd:u16be payload[len] [xor]
```

- `len` counts **payload bytes only**; `vendor + cmd` are part of the fixed
  8-byte prefix (maximum payload 255 bytes).
- If `flags & 0x01`, an XOR checksum of every preceding byte (from `FF`
  through the end of payload) is appended; verify it, and compute it with
  the flag bit set, as the device does.
- Decoders should resynchronise on `0xFF 0x01`: scan forward, try to decode,
  drop one byte on failure.
- A command `C` is acknowledged by the device as command `C | 0x8000` with
  payload `status:u8 [extra…]`, status `0` = success.

All commands below use vendor `0x000A` (QTIL).

| Command | Name | Notes |
|---|---|---|
| `0x0400` | FiiO getter | payload = one subcommand byte. `0x02` → ack payload `[0x00, 0x02, major, minor]`, i.e. `3.8` answers `[00, 02, 03, 08]`. |
| `0x4001` | REGISTER_NOTIFICATION | payload `0x12` (= `VM_UPGRADE_EVENT`) enables Upgrade events. |
| `0x4003` | EVENT_NOTIFICATION_CMD | unsolicited; payload `0x12 ‖ upgrade-message`. Must be ACKed (`0xC003`, status 0) promptly. |
| `0x0640` | UPGRADE_CONNECT | opens the upgrade session (one connect per transfer). |
| `0x0641` | UPGRADE_DISCONNECT | |
| `0x0642` | UPGRADE_CONTROL | payload = one upgrade message (host → device). |
| `0x0710` | RETRIEVE_PS_KEY | request payload `key:u16be`; ack = `status ‖ key:u16be ‖ word:u16be…`. Status `5` = key absent. |
| `0x0711` | RETRIEVE_FULL_PS_KEY | same shape, merged full-PS view (FiiO extension). Used to read the complete `PSKEY_BDADDR` (PS key 1 = 4 words). |
| `0x0712` | STORE_PS_KEY | see quirk below. |
| `0x0721` | SEND_APPLICATION_MESSAGE | payload = `event:u16be` (e.g. `0x478F` = stock `EventSysReboot`). |

## PS-key store quirk (FiiO firmware bug, and why you must pad)

The shipped handler converts the payload length from bytes to words **twice**:

```
effective_words = ((payload_len - 2) // 2 + 1) // 2
```

A conventional 40-byte payload for a 19-word key therefore stores only 10
words — this exact 10-word truncation is what an unmodified stock BTR15 shows
if you store key 4 naively. The stored data is simply `key ‖ words`, consumed
as `effective_words` from offset 2. To write N words, zero-pad the payload to
exactly `4N` bytes so the double adjustment passes exactly N to `PsStore`:

```
payload = key:u16be ‖ word0:u16be ‖ … ‖ wordN-1:u16be ‖ 0x00 × (4N − 2 − 2N)
```

Round-trip every store through the same model and read the key back before
trusting it. GAIA v1's one-byte length caps this at 63 words.

## Upgrade messages

Each upgrade message is `id:u8 ‖ len:u16be ‖ body`. Host→device messages are
carried in `0x0642` payloads; device→host messages arrive inside `0x4003`
notifications after the `0x12` byte.

| ID | Name | Body (host role) |
|---|---|---|
| 1 | `START_REQ` | empty |
| 2 | `START_CFM` | device→host: `status:u8 ‖ battery_mV:u16be`; status must be 0 and voltage ≥ 3900 mV |
| 3 | `DATA_BYTES_REQ` | device→host: `requested:u32be ‖ start_offset:u32be` |
| 4 | `DATA` | host→device: `last_flag:u8 ‖ bytes`; the final packet of the image is the only one with `last_flag = 1` |
| 7 / 8 | `ABORT_REQ` / `ABORT_CFM` | never send after the footer failure (see jailbreak doc) |
| 11 / 12 | `TRANSFER_COMPLETE_IND` / `_RES` | device signals end-of-staging; host accepts with body `0x00` |
| 13 / 14 | `IN_PROGRESS_IND` / `_RES` | device asks "still there?"; host answers `0x00` |
| 15 / 16 | `COMMIT_REQ` / `COMMIT_CFM` | commit after trial boot; accept is status 0 |
| 17 | `ERRORWARN_IND` | `code:u16be`. `0x003D` = `OEM_VALIDATION_FAILED_FOOTER`. **Do not** answer with 31; just ACK the GAIA notification |
| 18 | `COMPLETE_IND` | final, after commit |
| 19 / 20 | `SYNC_REQ` / `SYNC_CFM` | `SYNC_REQ` body = the 4-byte Upgrade ID (last 4 bytes of the package file). `SYNC_CFM` = `resume_point:u8 ‖ upgrade_id:u32be ‖ protocol:u8` |
| 21 | `START_DATA_REQ` | device restarts the data phase |
| 22 / 23 | `IS_CSR_VALID_DONE_REQ` / `_CFM` | poll during PRE_VALIDATE apply; CFM = `backoff_ms:u32be` (wait that long, poll again) |
| 24 | `SYNC_AFTER_REBOOT_REQ` | device-initiated sync |
| 31 | `ERRORWARN_RES` | forbidden on this route |

Data phase: the device requests up to 4096 bytes per `DATA_BYTES_REQ`, but a
GAIA packet fits at most 255 payload bytes, so the reference sender splits
into **240-byte** DATA bodies (252-byte GAIA packets) per request.

Resume points observed in `SYNC_CFM` / journal word 13:

| Value | Meaning |
|---|---|
| 0 | no staged update (clean) |
| 1 | `PRE_VALIDATE` — staged image waits for ordinary validation + copy (this is the jailbreak lever) |
| 3 | `POST_REBOOT` — used by the forbidden forced-swap shortcut |
| 6 | `ERROR` — footer validation failed |
| 8 | `IN_PROGRESS` — transfer/apply running |

## PS key 4: the upgrade-context journal

Key 4 is a 19-word `uint16` array — the non-volatile journal of the upgrade
state machine. Word 0 belongs to the sink application (bit 0 = GAIA transport
selection; `0x8001` = also carries a pending app-config reset request); the
upgrade library itself uses words 1–18 (`UpgradeInit()` receives the array at
word-1 offset). Observed states (example uses Upgrade ID `de ad be ef`;
`P` ∈ {`0x0001`, `0x8001`}):

```
clean journal (what a healthy preflight read returns):
  0001 0001 0000 0001 0000 0000 0000 0000 0000 0000
  0000 0000 0000 0000 0000 0000 0000 0000 0000

footer-failure journal (after staging a dev-signed package on stock P1,
example Upgrade ID de ad be ef; P = word 0, 0x0001 or 0x8001):
  P    0001 0001 0002 0000 0000 0001 0001 0001 0002
  0000 BEEF DEAD 0006 000A 0000 0000 0000 0000
                     ▲    ▲
                     │    └ vendor
                     └ word 13 = resume point (6 = ERROR)
words 11–12 = the staged Upgrade ID's two 16-bit halves in reverse
order (de ad be ef → BEEF DEAD)
```

After a **cold power cycle** the device itself normalises the journal: words
11–12 (the Upgrade ID) are cleared and nothing else changes — which is why
`SYNC_REQ` still accepts the ID you present and resume point 1 survives.

PS key 1 is `PSKEY_BDADDR` (4 words via `0x0711`; address
`AA:BB:CC:DD:EE:FF` reads back as `00DD EEFF 00CC AABB`). Reading it before
and after any flash is the cheap proof that device identity survived.
