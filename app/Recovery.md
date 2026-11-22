# BTR15 Tool — Recovery decision tree

Every device transaction (jailbreak stage, jailbreak resume, developer update,
stock-restore phase 1/2) is written to a crash-atomic journal
(`btr15-txn-<id>.journal` in the app's private files) **before** each state
boundary is crossed. If anything interrupts a run — Bluetooth drop, phone
reboot, power loss on the BTR15 — the journal survives, and the Firmware step
of the app shows a **Recover unfinished transaction** button. Recovery always
reads the live device state first (PS key 4 over `RETRIEVE_PS_KEY`) and takes
exactly one safe step.

Journals never contain the mnemonic, the developer key, or package bytes —
only digests, upgrade ids, phases and step notes.

A journal that exists but cannot be read is **not** treated as no journal. The
Firmware step says so in place of the usual summary, keeps **Recover unfinished
transaction** available (the device's own context is then the only evidence) and
offers **Discard unreadable record** as the way out. Every write goes to a temp
file, is flushed to disk and only then renamed over the journal; where the
platform will not replace the file in place, the old record is moved aside to
`…journal.prev` and read as the fallback, so a failed swap keeps the last
readable copy instead of deleting it.

## Inputs

- journal `kind` + `phase` + expected `package_sha256` / `staged_content_sha256`
  / `upgrade_id` + `device_address` + `official_uri`
- live key-4 words: resume word 13, staged-id words 11/12, dirty markers

Every journal records the MAC of the device the transaction started on, and
Recovery targets exactly that device — if the journal predates stamping or the
MAC is no longer bonded, Recovery stops and asks you to pick the device on the
Device step. It never picks a bonded BTR15 on your behalf, so a second
same-named speaker can never be flashed by mistake. A blank MAC is always
treated as "not recorded": the app refuses to stamp one, so the field can be
trusted when it is present.

The journal also records the URI of the official v3.8 file the transaction was
started from. After an app restart (which clears the wizard's memory) Recovery
re-opens that file itself — the picker holds a persistable read grant — and
checks it against the journal's `staged_content_sha256`. You are never asked to
find the file again, and a different file is still refused.

RSA-PSS signs with a fresh random salt, so `package_sha256` (the whole file,
signature included) only ever matches the exact staged bytes. After an app
restart the candidate is rebuilt from the official file and its footer bytes
differ; Recovery then identifies the transaction by `staged_content_sha256`
(the signed payload region — stable across rebuilds of the same variant) and
carries the upgrade id from the journal instead of re-deriving it.

## States and the single safe action

| Live resume word | Staged id | Meaning | Action taken by Recovery |
| --- | --- | --- | --- |
| 3 (POST_REBOOT) | matches journal | trial applied but the commit handshake was interrupted | reconnect loop, finish the commit (IN_PROGRESS → COMMIT → COMPLETE), verify clean |
| 3 (POST_REBOOT) | no journal match | a trial this app cannot identify | refuse; consult this file (device is running trial firmware; a cold power cycle rolls it back to the previous firmware) |
| 1 (PRE_VALIDATE) | 0/0 (cold-cycled) | jailbreak staged, device cold-cycled | run the zero-retransmit resume session (SYNC → START → IS_CSR → ImageUpgradeCopy), then commit, verify clean |
| 2 (VALIDATED) | matches journal | the image is staged and validated, but the host never acknowledged it (no reboot, no trial) | re-enter the session, poll the copy, serve any late data request, acknowledge completion, then commit and verify — the package is not transmitted again |
| 1 (PRE_VALIDATE) | still set | PRE_VALIDATE written but device has **not** cold-cycled | instruct: power the BTR15 off and on, then run Recovery again |
| 6 (ERROR) | matches journal, **jailbreak** journal | footer failed (0x003d), context journal left by the device | rewrite only word 13 (6 → 1) with the shipped STORE padding, read back, then power-cycle + resume |
| 6 (ERROR) | matches journal, **update** journal | a developer package was rejected by stock firmware | discard the staging: write the clean baseline context (verified by read-back) and delete the journal; the device keeps running exactly what it ran before. Recovery never writes PRE_VALIDATE here — that would jailbreak through an update you did not choose |
| 0, clean context | — | transaction already committed, or device rolled back | verify clean; delete the journal ("Finished interrupted commit") |
| 0, clean context | **stock restoration** record | phase 1 finished (or an attempt never got going) with the second phase still owed | phase 1 runs again only if it never committed; otherwise the record is re-armed at phase 2 and the official package is flashed and verified. The record is one transaction for both phases and is deleted only after phase 2 verified |
| 0, dirty markers | — | transfer power-lost mid-way | if the app still holds the exact staged bytes: run the transfer again — the device answers with its own skip offsets, so stored bytes are not retransmitted. If the app restarted (only a rebuild is possible): splicing a rebuild onto the partial staging would mix two different PSS tails, so Recovery writes the clean baseline, deletes the journal, and tells you to re-run the update from scratch |
| anything else | — | unexpected state | refuse to act; export the log |

## A jailbreak on a device that already trusts the key

The jailbreak checkpoint is the device's own refusal (`0x003d`). A device that
already trusts this signing key does not refuse: the package validates and the
device wants it installed. Rather than stopping at "already jailbroken", the
staging run continues as the **developer update** it really is — it polls
`IS_CSR_VALID_DONE`, sends `TRANSFER_COMPLETE_RES`, runs the POST_REBOOT commit,
verifies clean and retires the journal, so no cold cycle is needed. The same
holds for Recovery's re-run of an interrupted staging: if the device accepts the
package, the transaction completes instead of leaving a journal nothing would
continue.

Two consequences worth knowing:

- Polling is what makes this work. A device whose footer check passed says
  nothing until it is asked, so a passive wait sits out its whole budget in
  silence and looks like a timeout. It is not a rejection.
- Nothing is rewritten in key 4 on this path: the resume word only becomes
  PRE_VALIDATE when the footer actually failed.

## Manual fallbacks

- **Device holds a half-done upgrade but this phone has no journal** (journal
  discarded, app data cleared, another phone ran the attempt): press
  **Recover**. With no journal the only thing identifiable is the live key-4
  context, so Recovery writes the clean baseline back, proves it by read-back
  and reports — anything staged is inert and you re-run from scratch.
- **You want to abandon the transaction:** the Firmware step also offers
  **Discard unfinished transaction**, which deletes the journal only. The
  device context is not touched, so this is safe while the device has not been
  written to (no journal phase past `BEGIN`) and Recovery is the right tool
  afterwards if it has.

- **Device stuck showing trial firmware after a failed resume:** hold the
  power button for a full cold cycle. The BTR15 only promotes staged
  firmware after a validated `ImageUpgradeCopy`; otherwise it boots the
  previous image. Then run Recovery.
- **Recovery says the firmware file is wrong:** re-select the *same* official
  FiiO v3.8 file you used originally (`BTR15_V3.8.bin`,
  SHA-256 `26B21C1779BD9229B7256A055B1D1E55834A0EE48E500B6E0C952206911FDB39`).
  Recovery rebuilds the candidate locally and refuses anything whose signed
  content does not hash to the journal's recorded `staged_content_sha256`.
- **Two journals at once:** the tool refuses to act (this cannot happen
  through the UI; it guards against manual file edits).
- **Stock restore interrupted:** both phases are **one** journal record, stamped
  with the phase still owed. Recovery finishes it — phase 2 alone when phase 1
  already committed. If phase 1 committed and you power off before phase 2, the
  device runs stock payloads signed by the developer key — still fully
  functional, and phase 2 still continues from the same record. Starting
  **Restore stock** again also picks up at phase 2 rather than re-running
  phase 1, which the device would now reject because it trusts FiiO again.
- **Every dial dies seconds (or milliseconds) after connecting:** the BTR15
  hands out exactly one SPP/GAIA channel. Any other app on the phone (FiiO
  Control, serial monitors, older prototype tools such as
  `dev.codex.btr15*`) that grabs it makes every other client lose — the
  device tears the newcomer down instantly. Disable or force-stop those
  apps first; `logcat -s Btr15Link` plus `bt_stack` `port_api` lines show
  foreign dials the moment they happen. After force-stopping, power-cycle
  the BTR15 once so its side of any stale SPP lease is released, then run
  Recovery.

