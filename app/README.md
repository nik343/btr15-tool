# BTR15 Tool

Android app that patches, signs and flashes FiiO BTR15 firmware over
Bluetooth — entirely with code you can read and re-verify on this machine.
Four official Bluetooth releases have a pinned profile — **v2.2, v3.5, v3.8
and v4.4** — and a package outside that table is still worked on rather than
turned away, so a FiiO release published after this app was built is not a dead
end.

The app ships **no FiiO firmware and no private key**. You import an official
package yourself (for example `BTR15_V3.8.bin`); the app verifies its size and
SHA-256 against the pinned profile for that release, patches it locally, signs
it with a developer key derived from **your own** BIP-39 mnemonic
(deterministic BDKD-v1 → RSA-2048 Qualcomm modulus), and flashes it over the
same GAIA/Qualcomm Upgrade SPP protocol the official tool uses.

A package the table does not list is accepted when FiiO's own signature
verifies and FiiO's 514-byte key block can be found in exactly one place
(`Automute fix` / `100 Hz demo` availability is then decided by running the
real patch passes against that image). If the key block cannot be located, the
app says so on the firmware step and refuses to continue, because replacing
the key is the one thing it cannot improvise.

## What it does

- **Jailbreak (first install).** Stages the automute +
  developer-key package once; the device footer-check must reject it with the
  exact `0x003d` code; the tool then changes only Upgrade key 4's resume word
  (ERROR → PRE_VALIDATE), asks you to cold power-cycle the BTR15, and resumes
  with **zero retransmitted firmware bytes** — the device re-validates its own
  staged copy, runs the normal `ImageUpgradeCopy`, and the trial commit
  handshake finishes the jailbreak. If the device **already trusts** the key it
  does not refuse at all: the package validates and the run continues as the
  developer update it really is (commit, verify, no power cycle) instead of
  stopping at "already jailbroken".
- **Developer-key update.** Normal GAIA v1 / Qualcomm Upgrade transport with
  the device-driven data pump, the `IS_CSR_VALID_DONE` backoff loop and the
  POST_REBOOT trial commit handshake. Changes are **opt-in and honoured**: the
  developer key is always applied; the automute fix and the 100 Hz / 100 Hz2
  deadline menu are the two selectable extras, and the chosen combination is
  encoded in the variant name so Recovery rebuilds exactly those bytes. A
  package built without automute is refused if verification expects it, and
  vice versa.
- **Release-scoped changes.** The two extras are only offered where the
  release's own code can take them: the automute timer pair exists in v3.5 and
  newer (v2.2 has none), and the 100 Hz menu has only been written against
  v3.8's Apps P1. The row says why instead of hiding the option — `Automute fix
  (v3.5 and newer only)`, `100 Hz demo (only written for v3.8 at the moment)` —
  and keeps the plain name when it is grey only because "Restore stock
  firmware" is selected. The engine refuses an impossible combination even if
  one is somehow requested.
- **Every release, one engine.** v2.2, v3.5, v3.8 and v4.4 share the container,
  the FiiO signing key, the upgrade state machine and the journal vectors; only
  the package digests, the Apps P1 size, its manifest and where FiiO's 514-byte
  RSA block sits move. Those are pinned per release, and the block is also
  found by searching for its own bytes, so the wrong place can never be patched
  silently.
- **Unlisted packages are checked, not guessed.** For a package outside the
  four, the app requires FiiO's signature to verify and the same 514-byte block
  to occur exactly once — that is what makes "replace FiiO's key" safe — and
  then decides each optional change by running its real patch pass over the
  image: the automute anchors must match exactly once and begin with the live
  instruction, and the 100 Hz chain must find its sites, its extension offset at
  the end of Apps P1 and the partition-1 size word it rewrites (payload offset
  80). A grey row therefore means "this image's code cannot take it", not
  "the table does not mention it". When the key block cannot be located at all,
  the firmware step says why and **Continue stays disabled**; the jailbreak
  itself is left to you, since you know whether your build is susceptible.
- **Restore stock (two-stage).** Phase 1 flashes untouched official payloads
  re-signed by your developer key (restores the stock key block while staying
  flashable); phase 2 flashes the untouched official FiiO-signed package,
  which verifies again. Afterwards developer-key packages are rejected by the
  device — that is the correct stock end state. **Both phases are one
  transaction**: a single record carries the phase still owed and is deleted
  only after phase 2 verified, so an app close between the phases can never
  strand a device that already trusts FiiO again. Pressing Restore stock again
  finishes the recorded phase instead of starting over.
- **Recovery.** Every state boundary is journaled crash-atomically before it
  is crossed. Power loss, Bluetooth drops and reboots are resumed from the
  journal plus the device's own live key-4 state — including zero-retransmit
  resume of a staged image and skip-offset continuation of a half-transferred
  one. See [`Recovery.md`](Recovery.md) for the full decision tree.
- **A record that cannot be read is not a missing record.** Journal writes go
  to a temp file, are flushed to the medium and only then renamed into place;
  where the platform will not replace the file in place, the old record is set
  aside as `…journal.prev` and read as the fallback. An unreadable journal is
  reported on the Firmware step with Recovery still offered and a distinct
  **Discard unreadable record** way out, instead of silently looking like a
  clean phone.
- **It never guesses.** Each journal stamps the MAC the transaction started on
  and the URI of the official file it was built from, so Recovery retargets
  that exact device (a second, same-named BTR15 is never touched) and re-opens
  that exact file after an app restart — then still refuses anything whose
  signed content does not match the journal's digest.
- **Honest progress.** The status line names the phase the run has reached — one
  word per boundary the code actually crosses (`READING PACKAGE`, `SIGNING`,
  `CHECKING DEVICE`, `HANDSHAKING`, `WAITING FOR DEVICE`, `STAGING`,
  `VALIDATING`, `WAITING FOR REBOOT`, `COMMITTING`, `VERIFYING`, plus
  `CHECKING FOOTER` / `REWRITING CONTEXT` on the jailbreak, `RESUMING` after the
  cold cycle, `RECOVERING` / `REPAIRING CONTEXT` / `DISCARDING PACKAGE` in
  Recovery, and `STOCK 1 OF 2 ·` / `STOCK 2 OF 2 ·` prefixes during a stock
  restore). Detail goes to the log instead: while a package transfers the log
  carries a counter line for the percentage the device actually holds,
  `40% (3221/8061 packets)`, measured from the pump's own image offset. The
  packet total is the count the transfer will really end on — the messages
  already sent plus what the rest of the image still needs — because the
  device's own request windows decide how many DATA messages a package costs;
  a finished transfer therefore reads `8086/8086`, never past its own total.
  The screen and the exported log carry the line unchanged — the total is never
  stripped out.
  The lines are capped at one per ten-percent band and never closer than
  500 ms apart — eleven lines for a minutes-long transfer rather than one per
  message.
- **Transparency.** Hex-only protocol transcripts and process logs are
  exportable; the mnemonic never appears in any log or journal.
- **Files that are not firmware are cheap to refuse.** The picked file is read
  with an 8 MB cap (the four releases are about 1.9 MB each), so a wrong pick is
  refused while streaming instead of being buffered whole first.
- **The screen belongs to the system bars.** On Android 15 and later the app is
  drawn edge to edge (target SDK 35), so the real status/navigation-bar and
  cutout insets are taken as outer padding on the root: the header stays under
  the status bar and the Back/Continue actions stay above the navigation bar
  instead of sliding under either.
- **One app, no preview shell.** The wizard is the whole screen set; the power
  cycle screen runs only from a real transaction. The separate mock-up app used
  while the screens were designed is not part of this tree.

## Repository layout

```
app/
  src/main/java/app/btr15/tool/   the whole app, no dependencies beyond Android
    Bip39 / DevKey            mnemonic → deterministic RSA-2048 developer key (BDKD-v1)
    Pss                       RSA-PSS (SHA-256, MGF1, salt 222) sign/verify
    AppPackage                APPUHDR5 parse / assemble / signed-content
    FirmwareEngine            audited patches + RSA-PSS re-sign + self-verify
    Gaia / Upgrade / Session  GAIA v1 framing, Upgrade messages, session engine
    RfcommTransport           real SPP transport (reader thread + queue)
    Journal / Workflows       crash-atomic transactions + recovery tree
    DeviceOperator            plain-Java coordinator (also runs in JVM tests)
    TransferMeter             the log's transfer counter, with a derived packet total
    MainActivity / Btr15Connection   the wizard UI and Bluetooth discovery
  src/test/java/app/btr15/tool/   self-tests + a simulated BTR15 peer
```

## Requirements

A JDK with `javac`, and an Android SDK holding at least one platform and one
build-tools version that carries `aapt2`, `d8`, `zipalign` and `apksigner`. The
scripts look for the SDK in `work/android_sdk` beside the repo and for the JDK in
`JAVA_HOME`, then use the newest platform and build-tools they find. Pass
`-SdkRoot`, `-JavaHome`, `-AndroidPlatform`, `-BuildToolsVersion` or `-SigningDir`
to override, and expect each script to stop with the dependency it could not
find rather than guess at one. Nothing under `work/` is committed.

## Testing

JVM regression (no device needed) — BIP-39 vectors, key-derivation vectors,
protocol pins, CrossProof digests, package inspector, engine (140 checks: every
registered release builds and verifies, the mechanical probe agrees with the
pinned truth on all four, and an unlisted FiiO-signed package is described,
built and refused only when its key block is unusable), the
full workflow matrix against the simulated peer (117 checks: jailbreak
lifecycle, power-loss at every persistent-state boundary, dirty-transfer skip
resume, rollback, a silently dropped upgrade handshake, dead-journal residue,
journal hygiene incl. truncated-journal handling, a torn record read from its
sidecar, two unreadable copies reported instead of hidden, one record kept
across both stock phases in all three interruption forms, transcript safety)
and the
integration suite (174 checks) that drives the *exact*
`DeviceOperator` entry points the UI calls — stage → cold cycle → zero-byte
resume, developer update, two-stage stock restore, rejected-update cleanup,
crash-recovery through a rebuilt candidate, refusal of a mismatched official
file, the status line's phase order, the log's transfer counter for both
install methods and its derived packet total on a device that asks for
less than a full message at a time, a jailbreak switched into a developer
update on a device that already
trusts the key, a v3.5 developer update and a full v4.4 jailbreak through the
same pipeline, the single-client link-pool contract (settle on every
dial, SPP-record rotation) and device/source stamping:

The link rules the field audit forced are pinned mechanically, because the
BTR15 serves **one GAIA client** and advertises several SPP records under the
same UUID:

- exactly one physical link per wizard step; sessions borrow it and closing a
  session never drops the socket;
- every dial — including a step's first — waits the settle delay **after**
  closing every other client, so the firmware has actually released the
  previous one (closing it 209 ms before the new link came up let the device
  answer the cheap getters and drop every Upgrade message on that link);
- a socket that does not answer the firmware-version getter is closed and
  re-dialled (SDP then resolves a different record);
- the Device step's own probe socket is closed before the pooled link dials,
  so the device never sees two clients;
- a device that accepts the connection but answers no handshake message gets
  a fresh link, up to three times — nothing is staged at that point, so
  re-binding the single GAIA client is safe and is what the firmware needs.

Continuations after an app restart match the journal's
`staged_content_sha256` (deterministic payload region), never the whole-file
hash, and carry `upgrade_id` from the journal — an RSA-PSS rebuild produces
fresh footer bytes every time, so file-hash or re-derived-id comparisons
would reject legitimate continuations (the integration suite pins this).

```powershell
.\run-jvm-selftests.ps1     # must end with: ALL JVM SELFTESTS PASS
```

The matrix reads packages from a `fixtures\` folder beside the scripts — not committed: drop the official and developer-signed builds there, or pass `-Fixtures <dir>`.

APK build (compiles API-23-compatible sources, dexes, links, signs):

```powershell
.\build.ps1                 # → build\btr15-tool.apk
```

The APK is signed with the dedicated **release key** kept outside the app tree
in `work/release_signing/` (`btr15-release.keystore`, PKCS12, RSA-4096, password
in `password.txt` beside it) — the repo ships no private key. The script creates
the keystore, its password file and the certificate if the folder is empty and
reuses them afterwards, and it prints the signer certificate for checking. Keep
that folder backed up: Android only installs an update over a build signed by
the same certificate, so a lost key means an uninstall. The build is a release
build — `android:debuggable="false"`, so no debug runtime is shipped.

Testers moving off the old preview-signed build **must back the mnemonic up
first**: the certificate change forces the first install to be a fresh one
(`adb uninstall app.btr15.tool`), and that removes the app's saved identity.
Restore it from the backup on the Signing identity screen afterwards.

## Clockwork proof (PC ↔ phone cross-check)

```powershell
.\proof.ps1                                    # full: PC suites → APK → phone
.\proof.ps1 -PcOnly                            # PC only
```

The APK ships the frozen vector suites. `proof.ps1` starts the app with
`--ez run_selftest true`, which runs BIP-39, BDKD-v1, the GAIA wire-frame
pins and the pinned `CrossProof` digests **inside the Android runtime** and
writes the results to logcat; the script then diffs the phone's lines against
the PC's. Identical lines prove both machines derive bit-identical developer
keys and that RSA-PSS sign/verify (plus tamper rejection) behave identically
on the flashing machine and the phone. Manual equivalent:

```powershell
adb -s <serial> shell am start -n app.btr15.tool/.MainActivity --ez run_selftest true
adb -s <serial> logcat -d -s System.out:I Btr15Proof:I   # expect: XPROOF DONE PASS
```

What this does *not* prove: the radio link and the real BTR15 firmware's
behaviour. Those are covered by the proven message sequences (pinned in the
protocol suite), the fault-injection matrix, the journal + Recovery design,
and the hardware runbook below.

## Physical validation runbook (v3.8 only)

The release gate is this sequence on a real BTR15; the JVM matrix simulates
every one of these paths, but the hardware run is what ships the release:

1. Start from **stock v3.8**. Record section-10 + MAC (PS keys) and confirm
   the current firmware version in the app.
2. Jailbreak: stage → power-cycle checkpoint → resume with zero retransmit →
   confirm the automute behaviour and the new upgrade id on the device.
3. Developer-key update (100 Hz demo build) → confirm boot, menu, section-10
   and MAC unchanged.
4. Restore stock: phase 1 → phase 2 → device reports stock v3.8 again; a
   developer-signed package must now footer-fail (the jailbreak is gone).
5. Fault tests at each boundary (device off / BT drop): mid-stage, at the
   footer fail, after PRE_VALIDATE before and after the cold cycle, mid
   resume-commit, mid-update-transfer, between stock phases — Recovery must
   converge to a clean, working device every time.
