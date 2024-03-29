#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![no_std]

use core::fmt;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings.rs"));

impl fmt::Debug for mbedtls_blowfish_context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("mbedtls_blowfish_context").finish_non_exhaustive()
    }
}

impl Default for mbedtls_blowfish_context {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
