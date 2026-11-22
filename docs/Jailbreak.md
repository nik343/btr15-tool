# The Jailbreak: PRE_VALIDATE preserving bootstrap

Core observation: the sink application stages every `PARTDATA` payload to
the inactive bank **before** the running P1 validates the footer signature.
A dev-signed package therefore lands its bytes on the flash and the device
simply reports `ERRORWARN_IND 0x003D` (`OEM_VALIDATION_FAILED_FOOTER`). The
upgrade journal (PS key 4) records the failure as resume point `6` (ERROR).
The upgrade state machine, however, honors `resume = 1 (PRE_VALIDATE)` on
`SYNC_REQ`: that path skips all data transfer and hands the already-staged
image to **immutable P0's** ordinary validation + `ImageUpgradeCopy()` — the
exact same code a successful FiiO update uses, which is why device-only
sections are preserved. Nobody ever designed that path to be reachable with
an untrusted image, because the only writer of the journal was the failing
verifier itself.

Two constraints make the route safe:

- **Never set journal word 13 to `3` (`POST_REBOOT`) and never force a bank
  swap.** That resume path makes the update machinery bank-swap an image it
  was never meant to promote, and it destroys device-only configuration
  sections — including the factory Bluetooth identity, which no update
  package contains and whose loss forces the device onto a hardcoded
  fallback address. `PRE_VALIDATE
  (1)` is the only acceptable journal edit; it promotes the image through the
  *ordinary* copy path, which preserves every section absent from the
  package.
- **Staging is one-shot.** If any phase does not observe exactly the expected
  message sequence, stop and use the recovery tree below. Re-running a
  half-succeeded stage is how devices get wedged.

Prerequisites: firmware getter answers `3.8`, battery ≥ 3900 mV (per
`START_CFM`), journal key 4 reads the clean 19-word vector, and PS key 1
(read via `0x0711`) matches the MAC printed on your device — write it down,
it is your before/after proof. Build the dev-signed package first and verify
it offline ([Package-Format.md](Package-Format.md)) before touching the
device.

## Firmware scope

This route is not v3.8-specific. Every official BTR15 Bluetooth release
examined — v2.2, v3.5, v3.8, v4.4 — carries the same upgrade state machine:
all twenty `Upgrade`/`UpgradeSM` functions appear in each release with the
same or near-identical instruction sequences, only relocated. The
staging-before-verify ordering, the `0x003D` footer failure, the journal
vectors, and the `resume = 1` path are properties of that shared code, not
of the version number.

The container format is likewise unchanged between releases, and FiiO's
trusted-key constant block is byte-identical in all of them (SHA-256
`18FDF35D72FB776BBEC471924F570B331DB6822AF6B665C1F09696D11BE12CDF`,
relocated). Official images, for base verification:

| Release | Size (bytes) | SHA-256 |
|---|---:|---|
| v2.2 | 1,839,820 | `23CD28FE60D6613CBF6E099A0181234283A92880B36FD1F500AE2405DC9F1993` |
| v3.5 | 1,932,440 | `EAD376ABA18E344680DF8DBEBFD13014A16114F8AAB684B2B57A78E7022D74B6` |
| v3.8 | 1,932,460 | `26B21C1779BD9229B7256A055B1D1E55834A0EE48E500B6E0C952206911FDB39` |
| v4.4 | 1,927,696 | `940E15176FBAA8C037AFA6E78D9BC1D294BCB101947E4A695F38652BA90DA1A8` |

Every address in this repo is pinned to v3.8. On another release, re-derive
offsets from the documented context anchors; the message flow, journal
vectors, and recovery tree do not change.

## Phase 1 — stage once, fail exactly

Open SPP → `REGISTER_NOTIFICATION(0x4001, payload 0x12)` → `UPGRADE_CONNECT
(0x0640)`, each acked status 0. Then ordinary messages on `0x0642`:

1. `SYNC_REQ(UpgradeID)` → `SYNC_CFM(resume=0, id, proto)`.
2. `START_REQ` → `START_CFM(status=0, battery_mV)`.
3. Serve `DATA_BYTES_REQ(requested ≤ 4096, offset)` with `DATA` packets
   (240-byte bodies, `last_flag=1` only on the final packet) until the whole
   image is transferred.
4. Immediately after the last `DATA`, expect exactly one `ERRORWARN_IND`
   with body `00 3D` inside a GAIA `0x4003` notification. **ACK the
   notification (`0xC003`, status 0) and nothing else:** send no
   `ERRORWARN_RES`, no `ABORT_REQ`, keep the connection.

Anything else — a different code, an earlier error, a disconnect, a second
error — means stop: the transfer ended in an unexpected state, the image
is not reliably staged, and the journal
must not be touched.

## Phase 2 — repair the journal by exactly one word

5. `RETRIEVE_PS_KEY(4)` once. Require 19 words, byte-exactly equal to the
   expected footer-failure state ([Protocol.md](Protocol.md)): word 0 ∈
   {`0001`,`8001`}, words 1–10 = `0001 0001 0002 0000 0000 0001 0001 0001
   0002 0000`, words 11–12 = your Upgrade ID halves (swapped), **word 13 =
   `0006` (ERROR)**, word 14 = `000A`, words 15–18 = 0. Any deviation: stop.
6. `STORE_PS_KEY(4)` with the identical array except **word 13 → `0001`
   (PRE_VALIDATE)** — 4N zero-padded payload, [the FiiO handler quirk](Protocol.md#ps-key-store-quirk-fiio-firmware-bug-and-why-you-must-pad)
   applies. `RETRIEVE` again and require the stored array back. This is the
   only write to device state in the entire jailbreak; one word.

## Phase 3 — cold power cycle (the human step)

Power the BTR15 fully off and on. This is a literal physical boundary the
host cannot cross — the boot path runs its own journal normalisation: words
11–12 (the staged Upgrade ID) are cleared and the journal otherwise survives,
which turns "resume that ID" into "I have a staged image awaiting
validation, trust me, it's what *I* staged". A Bluetooth toggle or suspend is
not a cold cycle. Treat this as a hard checkpoint: no host action whatsoever
counts as performing it.

## Phase 4 — resume with zero bytes, normal copy

7. Reconnect (the device is back at its normal address), register,
   `UPGRADE_CONNECT`, `SYNC_REQ` with the **original Upgrade ID**.
   `SYNC_CFM` must answer `resume = 1`. If it says 0 (nothing staged) or 3
   (`POST_REBOOT`) **abort immediately** — do not stage again, go to the
   recovery tree.
8. `START_REQ` → `START_CFM(ok)`. Then poll `IS_CSR_VALID_DONE_REQ`; the CFM
   carries `backoff_ms` — sleep exactly that and poll again until validation
   is done (deadline 180 s). **No `START_DATA_REQ`, no `DATA_BYTES_REQ`, no
   firmware bytes travel at all** — P0 is validating what is already in the
   inactive bank and running `ImageUpgradeCopy()`, preserving every section
   absent from the package (P0, device identity, customer data).
9. `TRANSFER_COMPLETE_IND` arrives → answer `TRANSFER_COMPLETE_RES(0x00)`.
   The device trial-boots the custom image (SPP drops).

A validation failure anywhere in this phase rolls the bank state back on
boot; the previous image comes up and the journal returns to a repairable
state.

## Phase 5 — commit inside the trial window

v3.8 trial policy reverts to the previous image ~60 s after trial boot unless
the host commits over GAIA — and the BTR15 exposes no RFCOMM upgrade channel
while the trial image runs, so the window must be caught, not extended.
Reconnect promptly and run the ordinary commit exchange — `SYNC_REQ(ID)` →
`START_REQ` → accept `IN_PROGRESS_IND` with `IN_PROGRESS_RES(0x00)` →
`COMMIT_REQ` → `COMMIT_CFM(0)` → `COMPLETE_IND`.

If the window is missed the device rolls back to the previous image with the
journal in a repairable state; re-run from phase 2, or re-stage from scratch
if the staged image itself was rejected.

## Phase 6 — verify

Firmware getter still `3.8` (the version bytes are not patched); key 4 reads
the clean journal; key 1 via `0x0711` equals the MAC recorded before the
flash; audio unaffected. Journal every step host-side so any interruption
can be classified before acting.

## Subsequent updates

With a custom P1 trusted, later updates are boring: normal transfer,
signature verifies, `TRANSFER_COMPLETE_IND` → copy → trial → commit in the
same window. No journal edits ever again.

## Recovery tree for interruptions

| Observed state | Meaning | Action |
|---|---|---|
| clean journal (`1 1 0 1 0…`), nothing staged | link died before/at start | restart from phase 1 |
| footer state, word 13 = 6 | staged, awaiting repair | phase 2 |
| word 13 = 1, words 11–12 hold the ID | repaired, awaiting cold cycle | phase 3 |
| word 13 = 1, words 11–12 cleared | cold cycle done | phase 4 |
| word 13 = 8 (`IN_PROGRESS`) | transfer/apply live | wait; if permanently stuck, cold cycle then reassess |
| word 13 = 0 but words 11–12 still hold a staged ID (interphase stall) | state machine wedged between phases | send `EventSysReboot` **once**: `0x0721` payload `47 8F` (stock handler is `BootGetMode`→`BootSetMode`), expect the link to drop, reconnect, journal must read clean; never blind-retry |
| word 13 = 3 (`POST_REBOOT`) | a forced-swap tool has been here | stop; expect damaged device-only sections |

Rule of the whole tree: read state before writing anything, never store the
journal unless the readback matches the expectation exactly, and prefer
"abort and inspect" over "retry".
