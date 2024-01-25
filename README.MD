[apache-badge]: https://img.shields.io/badge/license-Apache--2.0-blue
[apache-link]: LICENSE-APACHE

[gpl-badge]:https://img.shields.io/badge/license-GPLv2%2B-blue
[gpl-link]: LICENSE-GPL


blowfish-mbed
=============

[![License: Apache-2.0][apache-badge]][apache-link]
[![License: GPLv2+][gpl-badge]][gpl-link]

This repository provides two crates for encryption and decryption of data using
the Blowfish cipher. While it is no longer recommended for usage in modern software,
this cipher can still be found in legacy code.

The crates in this repository are:

* `blowfish-mbed-sys` - direct bindings to *mbedtls*'s cipher implementation;
* `blowfish-mbed-c` - idiomatic Rust interface over the C bindings above.

## License

The implementation found in this repository is lifted *almost* directly from the
[mbedtls](https://github.com/Mbed-TLS/mbedtls) suite. To be more specific, from its
`2.28` branch, as Blowfish was removed from the library starting from 3.x versions.

Thus, licensing for this repository follows that of the original implementation.
Both crates are dual-licensed under `Apache-2.0` and `GPL-2.0-or-later`.
