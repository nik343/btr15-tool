## BTR15 tool

A jailbreak for the FiiO BTR15 DAC/Amp that installs persistent custom firmware through the device's own Bluetooth update path. 

### Contents

- [`docs/protocol.md`](docs/protocol.md) — GAIA v1 + Qualcomm Upgrade over Bluetooth SPP
- [`docs/package-format.md`](docs/package-format.md) — the `APPUHDR5` container, the RSA-PSS signature scheme
- [`docs/signing-key.md`](docs/signing-key.md) — how the trusted RSA key is stored inside Apps P1 and how it is replaced
- [`docs/patches.md`](docs/patches.md) — automute fix, developer signing key
- [`docs/jailbreak.md`](docs/jailbreak.md) — stage → expected `0x003d` rejection → one-word journal edit → cold power cycle → zero-byte resume → commit, including interruption recovery
- [`docs/stock-restore.md`](docs/stock-restore.md) — returning to genuine stock in two stages, with a way to prove that FiiO signatures are trusted again

As with any firmware flash, a botched update can brick the device. By trusting any documentation/procedure presented in this repo, you inherit the full risk of bricking your device. I am not responsible for any damages, but I will gladly help resolve issues if necessary.
This repository currently contains only exploit documentation, but a companion Android app that performs the whole flow on the phone will soon live here as well.