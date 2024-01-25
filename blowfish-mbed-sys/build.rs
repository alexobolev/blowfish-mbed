const OUTPUT_ARTIFACT: &str = "mbed-blowfish";

fn main() {
    cc::Build::new()
        .cargo_metadata(true)
        .cpp(false)
        .static_crt(true)
        .define("MBEDTLS_BLOWFISH_C", None)
        .define("MBEDTLS_CIPHER_MODE_CBC", None)
        .define("MBEDTLS_CIPHER_MODE_CFB", None)
        .define("MBEDTLS_CIPHER_MODE_CTR", None)
        .include("./")
        .include("./mbedtls/")
        .file("./mbedtls/blowfish.c")
        .file("./mbedtls/platform_util.c")
        .compile(OUTPUT_ARTIFACT);

    println!("cargo:rerun-if-changed=./mbedtls/");
}
