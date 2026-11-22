# Firmware Patches

## Automute removal (2 sites)

The ES9219MQ DACs' register 4 silence timer is initialised to `3` by FiiO's
DAC init for both chips (7-bit I²C addresses `0x48`/`0x49`), which mutes the
output almost immediately after audio stops (audible click/pop on pause;
distinct from the documented two-minute deep standby). Two MiniMode
instructions load that value; changing the register operand disables the
timer:

| Site | P1 offset | Package offset | Before | After |
|---|---|---|---|---|
| left DAC automute timer | `0x13CC` | `0x13DBB4` | `c4 20` (`r2 = 3`) | `04 00` (`r2 = 0`) |
| right DAC automute timer | `0x13FC` | `0x13DBE4` | `c4 20` (`r2 = 3`) | `04 00` (`r2 = 0`) |

Each site is located by its 14-byte context (`… 11 f0 35 eb …` distinguishes
the left DAC, `… 11 f0 25 ea …` the right), so a relocated future firmware
can be re-derived instead of blind-poked. The same pair is present in every
examined release: byte-identical at these offsets in v3.5; in v4.4 at P1
`0x14D2`/`0x1502` (package `0x13DCBA`/`0x13DCEA`).

## Developer signing key (1 site)

The 514-byte trusted-RSA constant block — format, offsets, replacement rules:
**[Signing-Key.md](Signing-Key.md)**. In package coordinates the v3.8 block
sits at `0x1D2EA4`.

With both edits applied, the package delta against the signed official v3.8
base is: four automute bytes, the 514-byte key block, and the re-signed
footer (a new signature ⇒ a new Upgrade ID). Everything else — every payload
length, the partition table, all other sections — stays byte-identical, so a
rebuild is checkable as an exact diff.
