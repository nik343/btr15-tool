# Product decisions

- A new signing identity is a standard 12-word BIP-39 mnemonic generated from
  128 bits supplied by Android's cryptographic random-number generator. Device
  identifiers are never entropy.
- The mnemonic is encrypted with a non-exportable Android Keystore key. It
  survives ordinary app closes and app upgrades. Uninstalling the app or
  clearing its data requires restoring the backed-up mnemonic.
- The mnemonic and private-key material must never appear in exported logs.
- Configuration is complete before flashing begins: firmware, signing
  identity, install method, changes, and target BTR15 are all selected first.
- The install method follows the signing identity by default, because the
  identity is what decides whether the device can already trust the key: a new
  mnemonic opens the Method step on **Jailbreak / first install** (the device
  cannot trust a key it has never seen), an existing mnemonic opens it on
  **Developer-key update** (that key may already be trusted, and the update
  needs no power cycle). Choosing on the Method step always wins for the rest
  of the run; picking an identity again re-applies its default. The Method step
  states the jailbreak's scope in place — `Supported firmware: v2.2, v3.5, v3.8
  or v4.4` — without gating anything: any firmware can still be taken down the
  jailbreak path, because whether it is susceptible is your call.
- Every change offered on the Changes step is optional and is honoured exactly:
  nothing is patched that you did not tick, the developer key being the
  only always-on edit. The selected combination is part of the package's
  identity, so Recovery restores the same package rather than an approximation.
- A change you did not tick is reported as inherited from stock, never as
  a patch: with no changes selected the package's only edit is the developer
  key block, and the export says exactly that.
- The four supported official releases (v2.2, v3.5, v3.8, v4.4) are data, not
  code paths: one pinned profile each (package digest, Apps P1 size and digest,
  manifest, key-block offset) and one engine. Where a release cannot take an
  optional change the row is greyed and names the reason in place —
  `Automute fix (v3.5 and newer only)` because v2.2's P1 has no timer pair, and
  `100 Hz demo (only written for v3.8 at the moment)` because the menu was
  written against v3.8's exact P1. Greying for a *choice* rather than a limit
  ("Restore stock firmware" owns the rows) keeps the plain name instead, so a
  grey row always says which of the two reasons applies. The engine refuses an
  impossible combination too, so a stale tick can never travel into a package.
- Firmware the table does not list is not turned away. A package is accepted when
  FiiO's signature verifies and FiiO's 514-byte RSA block occurs exactly once in
  it — the two facts that make replacing FiiO's key safe — and each optional
  change is then offered or greyed by running that change's real patch pass over
  the image (automute anchors, the 100 Hz site chain, its Apps P1 extension
  offset and the partition-1 size word at payload offset 80). Only a package
  whose key block cannot be located stops you at the firmware step, with
  the reason in the same warning element that lists the supported releases; the
  jailbreak's susceptibility is yours to judge, never the app's to predict.
- Confirmation includes the target's observed Bluetooth name, address, and
  installed firmware version.
- A target is accepted only after a live read-only BTR15 firmware-version query
  succeeds over RFCOMM/SPP.
- Bluetooth uses Android's public bonded-device and RFCOMM APIs. There is no
  fixed MAC address, ADB dependency, root requirement, phone-model assumption,
  or hidden channel-number fallback.
- The confirmation action is named **Flash** and opens a plain live process log.
  Any failure stops automatically and the complete non-secret log is
  exportable as a text file. Connection failures can export a diagnostic log
  from the Device step as well.
- The jailbreak is a trust test, not a ritual. Its checkpoint is the device's
  own `0x003d` refusal; a device that already trusts the key accepts the package
  instead, and the run continues as the developer update it is — commit, verify,
  retire the journal, no power cycle. Recovery applies the same rule when it
  re-runs an interrupted staging.
- Progress is reported in two places with two jobs. The status line names the
  phase the run has reached, one word per boundary the code actually crosses,
  and both stock-restore phases prefix theirs with their index (`STOCK 1 OF 2 ·`).
  Percentages are not a status: the log carries `40% (3221/8061 packets)`,
  driven by the pump's own image offset and reported at most once per
  ten-percent band and never twice inside 500 ms. The packet total is derived
  from the image still to go rather than assumed from the package size: the
  device grants bytes in its own windows, so a package always costs a few more
  DATA messages than "size ÷ 240" (the proven capture spent 8,080 on 1,933,208
  bytes, not the 8,056 the grid predicts). A fixed denominator is only a floor
  the real count overtakes — it once logged `100% (8086/8061 packets)` — so the
  meter reports the count the transfer will actually end on and lands exactly
  on the messages sent. A minutes-long transfer therefore costs eleven log
  lines instead of one per DATA message, and the export keeps all of them.
- The interface remains procedural, concise, square-cornered, white, and black,
  with explanatory text shown only where you need it to proceed safely.
- A stock restoration is **one** transaction, not two. Both phases share one
  journal record that names the phase still owed and is retired only after phase
  2 verified; starting Restore stock again with the record present continues it
  (phase 2 alone once phase 1 committed, because the device trusts FiiO again
  and would reject the developer-signed phase 1). The record's package digest
  still has to match, so a different official file is refused.
- A journal that exists but cannot be read is surfaced, never swallowed: the
  Firmware step says why, keeps Recovery reachable (the device's own context is
  the only evidence left, and the orphan repair is the honest step), and offers
  **Discard unreadable record** as the way out. Writes flush to the medium before
  being renamed into place, and where an in-place replace is impossible the last
  readable copy is set aside as `…journal.prev` and used as the read fallback
  instead of being deleted first.
- Reads are capped at 8 MB while streaming, so a wrong pick is refused before it
  is buffered whole; the four supported packages are about 1.9 MB each.
- The window is drawn edge to edge on Android 15+ (target SDK 35) and the real
  system-bar and cutout insets become root padding, so the footer actions can
  never end up under the navigation bar.
- The app ships as a release build (`debuggable="false"`) signed with a dedicated
  release key kept outside the repo. The preview flag entry points and the
  embedded power-cycle preview mode are gone: the power-cycle screen runs only
  from a real transaction, and the offline mock-up was a separate throwaway app
  that is not part of this tree. Anyone moving from the preview certificate has to
  back the mnemonic up, because the first install over it must be a fresh one.
