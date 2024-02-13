[apache-badge]: https://img.shields.io/badge/license-Apache--2.0-blue
[apache-link]: LICENSE-APACHE

[gpl-badge]:https://img.shields.io/badge/license-GPLv2%2B-blue
[gpl-link]: LICENSE-GPL

[gha-badge]: https://img.shields.io/github/actions/workflow/status/alexobolev/blowfish-mbed/build.yml
[gha-link]: https://github.com/alexobolev/blowfish-mbed/actions/workflows/build.yml

[crates-c-badge]: https://img.shields.io/crates/v/blowfish-mbed-c.svg
[crates-c-link]: https://crates.io/crates/blowfish-mbed-c

[docs-c-badge]: https://img.shields.io/docsrs/blowfish-mbed-c
[docs-c-link]: https://docs.rs/blowfish-mbed-c/latest/blowfish_mbed_c

[crates-sys-badge]: https://img.shields.io/crates/v/blowfish-mbed-sys.svg
[crates-sys-link]: https://crates.io/crates/blowfish-mbed-sys

[docs-sys-badge]: https://img.shields.io/docsrs/blowfish-mbed-sys
[docs-sys-link]: https://docs.rs/blowfish-mbed-sys/latest/blowfish_mbed_sys


blowfish-mbed
=============

[![Build status][gha-badge]][gha-link]
[![License: Apache-2.0][apache-badge]][apache-link]
[![License: GPLv2+][gpl-badge]][gpl-link]

This repository provides two crates for encryption and decryption of data using
the Blowfish cipher. While it is no longer recommended for usage in modern software,
this cipher can still be found in legacy code.

The crates in this repository are:

* `blowfish-mbed-sys` - direct bindings to *mbedtls*'s cipher implementation;
    * [![crates.io (sys)][crates-sys-badge]][crates-sys-link] [![docs.rs (sys)][docs-sys-badge]][docs-sys-link]

* `blowfish-mbed-c` - idiomatic Rust interface over the C bindings above.
    * [![crates.io (c)][crates-c-badge]][crates-c-link] [![docs.rs (c)][docs-c-badge]][docs-c-link]

## Backlog

The `blowfish-mbed-c` crate only wraps ECB and CBC modes of operation yet.

It would be a good idea to also provide a safe interface for the CFB and CTR modes
for completeness' sake, since `mbedtls` already implements those.

## License

The implementation found in this repository is lifted *almost* directly from the
[mbedtls](https://github.com/Mbed-TLS/mbedtls) suite. To be more specific, from its
`2.28` branch, as Blowfish was removed from the library starting from 3.x versions.

Thus, licensing for this repository follows that of the original implementation.
Both crates are dual-licensed under `Apache-2.0` and `GPL-2.0-or-later`.
