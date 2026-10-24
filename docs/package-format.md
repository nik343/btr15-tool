# Update package format: `APPUHDR5` / `PARTDATA` for `$QCC512Xx`

A FiiO BTR15 Bluetooth update (`.bin`, ~1.9 MB) is Qualcomm's standard
QCC512x OTA container. Nothing about it is FiiO-secret; the public ADK
tooling generates the same structure.

## Container

```
APPUHDR5 magic ("APPUHDR5")
u32be    header length
"$QCC512Xx" target magic
…        header remainder

then, in order, one record per partition payload:

u32be    record size      (includes these 4 bytes)
u16be    type
u16be    number
bytes    payload          (record size − 8 bytes)

footer, at the end of the file:

"APPUPFTR"
u32be    signature length (0x100)
bytes    256-byte RSA-2048 signature
```

The **last four bytes of the file are the signature's tail — and the device
treats exactly those four bytes as the Upgrade ID** echoed back in
`SYNC_CFM`. Any new package therefore needs a fresh footer (new signature ⇒
new Upgrade ID).

## Signature

- The **signed content is the concatenation of the record payloads in file
  order only** — headers, record headers and the footer are not covered.
- Algorithm: RSA-2048, exponent 65537, **RSASSA-PSS**, SHA-256, MGF1-SHA256,
  salt length **222** (the maximum: 256 − 32 − 2). Verifiers must accept the
  maximum-salt form explicitly.
- The verifying public key is *not* in the package. It is compiled into the
  Apps P1 program running on the device (see [signing-key.md](signing-key.md)).

Because the header is unsigned and partition payloads are staged to bank
**before** footer validation, the footer check happens in the running P1
software — after the bytes are already on the flash. That ordering is what
the jailbreak exploits.

## Verified v3.8 profile

| Property | Value |
|---|---|
| Official v3.8 package size | `0x1D7CAC` = 1,932,460 bytes |
| Official v3.8 package SHA-256 | `26B21C1779BD9229B7256A055B1D1E55834A0EE48E500B6E0C952206911FDB39` |
| Target string | `$QCC512Xx` |
| Footer | `APPUPFTR` at offset `0x1D7BA0`, length `0x100` |
| Partition payload table (type, number, payload size) | `(0,0,16)` `(0,1,272)` `(0,4,10872)` `(0,5,572112)` `(0,6,69968)` `(0,7,642960)` `(0,9,635832)` |
| Partition (0,9) = Apps P1 | package offset `0x13C7E8` (after its 4-byte partition id), size `0x9B3B8` |
| Apps P1 SHA-256 | `94A11359EFB932897C1406D02199CE9B42A62F9EE0C53FF7E40F5ACDB51DB113` |
| Firmware getter | `3.8` |

A correct rebuild keeps every payload byte for byte and changes only the
footer (and therefore the Upgrade ID). Before flashing anything, verify the
base package against the pinned SHA-256 above, then independently
re-verify any rebuilt package: structure, digests, and the PSS signature
over the reconstructed signed content.

## What the package never contains

Device-specific data is absent from every official package: Apps **P0**
(the immutable first-stage application), the device read-only identity
filesystem (one record holding `PSKEY_BDADDR`), and customer/production
banks. During a normal copy, P0's `ImageUpgradeCopy()` preserves sections
that are absent from the package — which is why promoting an image through
the copy path in [jailbreak.md](jailbreak.md) leaves the Bluetooth identity
intact.
