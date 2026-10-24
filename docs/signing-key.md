# The trusted RSA key lives inside Apps P1

Firmware signature verification runs in the QCC sink application (Apps P1
links `upgrade`, `rsa_decrypt`, and `rsa_pss_constants`). The trusted RSA-2048
public key is a compile-time constant *inside the P1 program*, so replacing
that constant is all it takes to make a modified P1 trust a new signing
identity — including its own future updates.

## The constant block

In v3.8 Apps P1 the FiiO key is a **514-byte block at P1 offset `0x966BC`**
(SHA-256 of the stock block: `18FDF35D72FB776BBEC471924F570B331DB6822AF6B665C1F09696D11BE12CDF`).
Layout in the device's "XAP" storage form — every uint16 stored with its two
bytes swapped:

```
bytes 0..255    modulus n, byte-pair swapped
byte  256..257  M_dash, uint16 little-endian = (−(n_low16)⁻¹) mod 2¹⁶
bytes 258..513  R² mod n (R = 2²⁰⁴⁸), byte-pair swapped
```

`n_low16` is the low 16 bits of the big-endian modulus (its last two bytes).
The exponent 65537 is not stored; it is fixed in the code. Producing the
replacement block is a dozen lines:

```python
def qcc_rsa_constant_block(n: int) -> bytes:
    modulus = n.to_bytes(256, "big")
    low16 = int.from_bytes(modulus[-2:], "big")
    m_dash = (-pow(low16, -1, 1 << 16)) & 0xFFFF
    r_squared = pow(2, 4096, n).to_bytes(256, "big")
    swap = lambda b: b"".join(b[i : i + 2][::-1] for i in range(0, len(b), 2))
    return swap(modulus) + m_dash.to_bytes(2, "little") + swap(r_squared)
```

FiiO's v3.8 release modulus (canonical big-endian; recovered from the
authenticated Apps P1, relocated but identical in v4.4 — public key data that
ships in their firmware):

```
b4d9af43f43b603ee78c32bea167560b841628a633be8ac3f9ce4a14f6eb2f71
f3b9d21438b010670226ff953dfadf68b78b86eccce30e16870adaa012a8f51c
d99c2fe3742d880bf81580e20082972fdc895130775b0a4598f6d9331fb80d39
c6a5dfefa4a9df0a2a36d1e78dafc44f0ac2113cd072d8da713f14b6a73808b
460d160fa5a7430f201bdff24fcf099db2014058ca60c469906cbb5a1aafc92
b4f57315477ac78a2f4bc39ba31b7eb379ec64996d3971df70dbe265577476a
1d550088656bcc4e5610a22c05ff1ff2e44d2ffb9e046a071b3d01150340ca4
e69e9602b2fff47472cc277c0f44e5c745278304fb9771262519cac24673957c
040b
```

## Replacement rules

- Locate the stock block by offset **and** require its SHA-256 to match
  before replacing; after replacing, require the old block to be *absent*
  anywhere in P1 (an override that leaves the FiiO block alive would keep
  accepting stock images and mask mistakes).
- The replacement is size-neutral, so every payload length, partition table
  and the automute context anchors stay intact; the whole delta of a key
  replacement is exactly 514 bytes.

Once the custom P1 boots, the device accepts **ordinary, correctly signed
packages from the new private key** through the normal accepted-signature
path: stage, `TRANSFER_COMPLETE_IND`, copy, trial boot, commit. No journal
trickery on subsequent updates. Conversely, genuine FiiO-signed packages are
rejected with `0x003D` while a custom P1 is trusted — the proof step in
[stock-restore.md](stock-restore.md).

## The developer key

Any RSA-2048 keypair with public exponent 65537 works as the trust anchor:
the public half becomes the 514-byte block above inside the image, and every
subsequent package is signed with the private half. The private key is the
root of trust for all future updates to devices that carry that key — back it
up like the vault it is.

**Anyone holding the private key can sign images for devices that trust it.**
