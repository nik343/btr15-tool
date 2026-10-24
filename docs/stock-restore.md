# Returning to genuine stock — two stages plus proof

While a custom Apps P1 is running, the device trusts the developer key and
rejects FiiO-signed packages with `0x003D`. Flashing the untouched FiiO file
directly is therefore impossible — chicken-and-egg. The return to stock has
to be staged, and then *proven*:

## Stage 1 — dev-signed package with byte-exact stock payloads

Rebuild an `APPUHDR5` container whose seven `PARTDATA` payloads are copied
byte-for-byte out of the verified official v3.8 package (including the
genuine P1 with the genuine FiiO key block and the genuine automute
instructions), then sign it with **your developer key** — a new footer, a
new Upgrade ID, everything else identical. This rides the ordinary
developer-trusted update path: transfer, validation,
`TRANSFER_COMPLETE_IND`, P0 copy, trial boot, commit inside the window. No
journal edits.

After this phase the flash contents are bit-identical to stock v3.8 — the
device is *functionally* restored. What remains is to prove the trust root
itself came home, because stage 1's signature was yours.

## Stage 2 — the untouched official package

Run a normal update with the original, unmodified FiiO v3.8 `.bin` (verified
against the pinned SHA-256 first). Its genuine signature now validates
against the restored FiiO key block, and the accepted-signature path proves
the genuine trust chain works end to end.

## Proof of rejection (the device is really stock again)

Build a dev-signed candidate (any patch set) and stage it exactly like
[jailbreak.md phase 1](jailbreak.md). A genuine stock device must answer the
completed transfer with exactly `ERRORWARN_IND 0x003D`. If it were accepted,
your custom key would still be trusted and the restore would have silently
failed.

After the proof, choose deliberately:

- **Stop here** — the journal sits in the footer-failure state (word 13 = 6,
  staged ID present). Send one `EventSysReboot` (`0x0721` payload `47 8F`),
  let the link drop, reconnect, and confirm the journal reads the clean
  vector. Device is stock, clean, done.
- **Continue into a re-jailbreak** — from the footer-failure state, the
  jailbreak simply resumes at [phase 2](jailbreak.md#phase-2--repair-the-journal-by-exactly-one-word);
  the staged candidate you just used as proof is the image that gets
  promoted, so one session can chain stage → rejection → repair → cold
  cycle → zero-byte resume → commit without any rebuild.

## What restoration never touches

Apps P0 is immutable from this side of the interface and is never in any
package. The device identity store is likewise absent from every package and
preserved by the copy path — restore walks the same `ImageUpgradeCopy()`
code a normal FiiO update does. The factory MAC is verified with `0x0711`
reads before phase 1 and after phase 2.
