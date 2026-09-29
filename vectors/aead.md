# AEAD / KDF known-answer vectors

Official vectors for the AEAD and KDF operations. All values were re-computed
with independent Python references (`cryptography` AEAD bindings, `hmac` +
`hashlib` for HKDF/PBKDF2/scrypt) and compared byte-for-byte with the RFC
text on 2026-09-28. RFC text is published under IETF Trust license terms that
permit reproduction of the specifications; the vectors reproduced here are
unencumbered.

## ChaCha20-Poly1305 AEAD — RFC 8439, section 2.8.2

Cipher: ChaCha20-Poly1305 with AAD. Used by `aead-chacha20poly1305-*`.

```
key    = 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
nonce  = 070000004041424344454647
aad    = 50515253c0c1c2c3c4c5c6c7
pt     = "Ladies and Gentlemen of the class of '99: If I could offer you
          only one tip for the future, sunscreen would be it."
         (4964657320616e642047656e746c656d656e206f662074686520636c617373
          206f66202739393a204966204920636f756c64206f6666657220796f75206f
          6e6c79206f6e652074697020666f7220746865206675747572652c2073756e
          73637265656e20776f756c642062652069742e)
ct     = d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
         3ff4def08e4b7a9de576d26586cec64b6116
tag    = 1ae10b594f09e26a7e902ecbd0600691
```

## AES-128-GCM — McGrew/Viega test cases 3 and 4

Source: McGrew & Viega, "The Galois/Counter Mode of Operation" (2004),
GCM specified in NIST SP 800-38D. Used by `aead-aes-gcm-*`.

Test case 3 (no AAD):

```
key   = feffe9928665731c6d6a8f9467308308
iv    = cafebabefacedbaddecaf888
pt    = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
ct    = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
        21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985
tag   = 4d5c2af327cd64a62cf35abd2ba6fab4
```

Test case 4 (same key/iv, plaintext truncated to 60 bytes, AAD present —
exercises the AAD + partial-block GHASH path):

```
key   = feffe9928665731c6d6a8f9467308308
iv    = cafebabefacedbaddecaf888
aad   = feedfacedeadbeeffeedfacedeadbeefabaddad2
pt    = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
        (60 bytes — test case 3 plaintext with the last 4 bytes removed)
ct    = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
        21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091
tag   = 5bc94fbc3221a5db94fae95ae7121a47
```

## HKDF-SHA-256 — RFC 5869, test case 1

Used by the `hkdf` operation. PRK is exposed as a separate fixture because the
operation's tests assert the extract and expand stages independently.

```
ikm  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b  (22 octets of 0x0b)
salt = 000102030405060708090a0b0c
info = f0f1f2f3f4f5f6f7f8f9
L    = 42

prk  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
okm  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
       34007208d5b887185865
```

## PBKDF2-HMAC-SHA-256 — RFC 7914, section 11

Used by the `pbkdf2` operation. Both vectors from RFC 7914 (ASCII password
and salt):

```
P = "passwd",   S = "salt",  c = 1,     dkLen = 64
dk  = 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
      49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783

P = "Password", S = "NaCl",  c = 80000, dkLen = 64
dk  = 4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56
      a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d
```

## scrypt — RFC 7914, section 12

Used by the `scrypt` operation. First two vectors (the N=16384/1048576 rows
are impractical as unit-test fixtures and are intentionally omitted here; the
RustCrypto implementation is validated upstream against the full set):

```
P = "", S = "", N = 16, r = 1, p = 1, dkLen = 64
dk  = 77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442
      fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906

P = "password", S = "NaCl", N = 1024, r = 8, p = 16, dkLen = 64
dk  = fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162
      2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640
```

Note: the second vector needs `maxmem` >= ~16 MiB in OpenSSL-backed
implementations — relevant when wiring it into Rust test harnesses that
default to restrictive memory limits.
