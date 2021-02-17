---
EEP: 8
title: EOSIO private key encryption
author: Johan Nordberg <eosio@johan-nordberg.com>
status: Draft
type: Standards Track
category: Interface
created: 2021-02-17
---

## Abstract

A method is proposed for encrypting and encoding EOSIO private keys in the form of a `SEC_<keyType>_<base58CheckPayload>` string. Encrypted keys are intended for use when transmitting or storing private keys on untrusted mediums. Each `SEC_..` string record contains all the information needed to reconstruct the private key except for the passphrase.

## Motivation

TODO
 - Printing on untrusted printers
 - Standardised encryption used by wallets
 - Owner keys should be offline
 - Brute force resist

## Specification

Encrypted keys are encoded using the same convention as EOSIO public and private keys, `SEC_` followed by key type e.g. `K1_` followed by the base58Check-encoded (Note: The EOSIO base58Check-variant uses `ripemd160(keyType + payload)` not `double_sha256(payload)[4:]`) payload.

The payload consists of a 1-byte header containing the scrypt parameters, a 4-byte checksum of the public key followed by the encrypted key data.

The header byte is converted to the N, r & p scrypt params as follows:

first 3 bits is N as power of two starting at 14
next 3 bits is r as power of two starting at 3
last 2 bits is p as a power of two

This makes the easiest possible scrypt params `0x00` N=16384 r=8 p=1 (matching the 2009 scrypt paper recommendation and is what Bitcoin's BIP 38 uses) and the hardest `0xff` N=2097152 r=1024 p=16.

The checksum is the first 4 bytes of `double_sha256(public_key_str)` (`PUB_<keyType>_..` not legacy `EOS..` key).

And finally the last bytes are the private key data, the size of the key data may vary based on key type. For R1 and K1 keys the data is 32-bytes.

### Encrypting a private key

- Given the key `PVT_K1_jsufMdV436e3vbj45mUXNESb3juT6LFDj7rpr7Ar3Gajf3f5G`, password `foobar` and scrypt params N=32768 p=16 r=1
- Calculate the 4-byte checksum by deriving the public key from the private key, converting it to a `PUB_` format string and take the first 4 bytes from running `sha256(sha256(ascii_bytes_pubkey_string_bytes))`
- Calculate a 48-byte scrypt hash using the password, params and checksum as a salt
- Encrypt the private key data using AES_CBC using the first 16 bits of the scrypt hash the iv and the remaining 32-bytes as the encryption key
- Calculate the header byte by setting the first 3 bits to `log2(N) - 14`, next 3 bits to `log2(r) - 3` and last 2 bits to `log2(p)`.
- Encode header byte + checksum + encrypted private key data using base58 check and prepend `'SEC_' + key_type + '_'`
- Result is `SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj`

### Decrypting a private key

- Given the encrypted key `SEC_K1_8vWLjFLTcvWNKY8wwfMKJJ3Sf278qb5xQgqXFzrRF44ECxACwoC3RPTj` and password `foobar`
- base58check decode the encrypted key data
- Calculate the scrypt params from the header byte
   - `N = pow2(((header & 0xE0) >> 5) + 14)`
   - `r = pow2(((header & 0x1C) >> 2) + 3)`
   - `p = pow2(header & 0x03)`
- Get the checksum from the 4 bytes after the header
- Calculate a 48-byte scrypt hash using the password, params and checksum as a salt
- Decrypt the private key data using AES_CBC using the first 16 bits of the scrypt hash the iv and the remaining 32-bytes as the encryption key
- Calculate the 4-byte checksum by deriving the public key from the decrypted private key
- Verify that the checksums matches
- Result is `PVT_K1_jsufMdV436e3vbj45mUXNESb3juT6LFDj7rpr7Ar3Gajf3f5G`

### Choosing Scrypt params

TODO
 - As high as you can get away with.
 - https://stackoverflow.com/a/30308723

## Acknowledgements

This standard is inspired by Bitcoin's [BIP 38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki).

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).