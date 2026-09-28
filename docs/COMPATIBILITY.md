# Compatibility

Upstream capability baselines. Per-feature tracking lives in
`compatibility/*.toml` (statuses: covered, superset, partial, missing,
intentional-out-of-scope, same-capability). CI generates coverage reports as
the matrices mature.

CyberCipher is an independent project; these baselines guide capability and
UX coverage, not architecture or code. Success is not raw operation count —
features CyberChef has that are irrelevant to a CTF-oriented crypto workbench
are marked `intentional-out-of-scope` with a reason.

## cyberchef.toml (initial, Milestone 1 scope)

| CyberChef operation | Ours | Status | Notes |
|---|---|---|---|
| From/To Hex | from-hex / to-hex | covered | strict + relaxed modes |
| From/To Base64 | from-base64 / to-base64 | covered | std + URL-safe alphabets |
| From/To Base32 | from-base32 / to-base32 | covered | std + base32hex |
| From/To Base64url | from-base64 (urlsafe) / to-base64 | covered | alphabet parameter |
| URL Decode/Encode | from-url / to-url | covered | `+`-as-space option |
| From/To Binary, Octal, Decimal | from/to-binary, -octal, -decimal | covered | |
| To Hexdump | to-hexdump | partial | no configurable width yet |
| Reverse | reverse | covered | bytes/chars |
| Split / Join | split / join | partial | regex delimiter not yet supported |
| XOR | xor | partial | standard/rolling/incrementing; no key-differential schemes yet |
| Bitwise AND/OR/NOT | bitwise-and/or/not | covered | |
| Rotate left/right | rotate-left/right | covered | per-byte rotation |
| Swap endianness | swap-endianness | covered | |
| Entropy | entropy | partial | no conditional-entropy chart yet |
| Strings | strings | covered | |
| UTF-8 decode/encode | decode-text / encode-text | covered | |
| AES Decrypt/Encrypt | aes-decrypt / aes-encrypt | partial | ECB/CBC/CTR/CFB/OFB + PKCS7/Zero/ISO7816; GCM/CCM/EAX/OCB AEAD still missing |
| DES / 3DES | des-decrypt / des-encrypt | partial | ECB/CBC; no CFB/OFB for DES |
| RC4 | rc4 | covered | includes RC4-drop[n] |
| SM4 | sm4-decrypt / sm4-encrypt | partial | ECB/CBC/CTR/CFB/OFB |
| TEA/XTEA/XXTEA | tea/xtea/xxtea encrypt/decrypt | covered | CyberChef parity for block ops |
| MD5 / SHA-1 / SHA-2 | md5, sha1, sha224/256/384/512 | covered | |
| SHA-3 / Keccak / SHAKE | sha3 (variant param) | covered | SHAKE output-length param |
| SM3 | sm3 | covered | |
| HMAC | hmac | partial | MD5/SHA-1/SHA-256/SHA-512/SHA3-256/SM3 variants |
| Compression ops | — | missing | Milestone 9 |
| Magic / Auto Decode | — | missing | Milestone 3 |
| RSA / ECC ops | — | missing | Milestone 4/8 |

## toolsfx.toml / auto-ctf-crypto.toml

Not yet written. They will be introduced together with the crypto and attack
milestones so that entries start from real implementation status instead of
aspirations.
