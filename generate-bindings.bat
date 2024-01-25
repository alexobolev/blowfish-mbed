bindgen .\blowfish-mbed-sys\mbedtls\blowfish.h -o .\blowfish-mbed-sys\bindings.rs --use-core --allowlist-function mbedtls_blowfish_.+ --allowlist-type mbedtls_blowfish_.+ --allowlist-item MBEDTLS_BLOWFISH_.+ --allowlist-item MBEDTLS_ERR_.+ --no-derive-debug --no-doc-comments --default-visibility private -- -Iblowfish-mbed-sys -Iblowfish-mbed-sys\mbedtls -DMBEDTLS_CIPHER_MODE_CBC -DMBEDTLS_CIPHER_MODE_CFB -DMBEDTLS_CIPHER_MODE_CTR
