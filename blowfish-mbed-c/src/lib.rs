#![allow(dead_code)]
#![allow(unsafe_code)]

use std::cell::UnsafeCell;
use std::ops::RangeInclusive;

use blowfish_mbed_sys::*;
use thiserror::Error;


#[derive(Clone, Debug, Error)]
pub enum BlowfishError {
    #[error("error code unknown: {0}")]
    Unknown(i32),
}


const KEY_BYTES_MIN: usize = MBEDTLS_BLOWFISH_MIN_KEY_BITS as usize / 8;
const KEY_BYTES_MAX: usize = MBEDTLS_BLOWFISH_MAX_KEY_BITS as usize / 8;
const KEY_BYTES_RANGE: RangeInclusive<usize> = KEY_BYTES_MIN ..= KEY_BYTES_MAX;


#[derive(Clone, PartialEq, Eq)]
pub struct BlowfishKey {
    bytes: [u8; KEY_BYTES_MAX],
    size: usize,
}

impl BlowfishKey {
    pub fn new(slice: &[u8]) -> Option<Self> {
        if KEY_BYTES_RANGE.contains(&slice.len()) {
            let mut instance = BlowfishKey {
                bytes: [0u8; KEY_BYTES_MAX], size: slice.len(),
            };
            instance.slice_mut().clone_from_slice(slice);
            Some(instance)
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn slice(&self) -> &[u8] {
        // SAFETY: Keys cannot be constructed with size out of bounds.
        unsafe { self.bytes.get_unchecked(.. self.size) }
    }

    #[inline(always)]
    pub fn slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: Keys cannot be constructed with size out of bounds.
        unsafe { self.bytes.get_unchecked_mut(.. self.size) }
    }

    #[inline(always)] pub fn is_empty(&self) -> bool { false }
    #[inline(always)] pub fn len(&self) -> usize { self.size }

    #[inline(always)] pub fn bits(&self) -> u32 { self.size as u32 * 8 }
    #[inline(always)] pub fn data(&self) -> *const u8 { self.slice().as_ptr() }
}


pub const BLOCK_SIZE: usize = MBEDTLS_BLOWFISH_BLOCKSIZE as usize;

const MODE_DECRYPT: i32 = MBEDTLS_BLOWFISH_DECRYPT as i32;
const MODE_ENCRYPT: i32 = MBEDTLS_BLOWFISH_ENCRYPT as i32;

#[inline(always)]
fn for_each_block<const SIZE: usize, CB>(input: &[u8], output: &mut [u8], callback: CB)
where
    CB: Fn(&[u8; SIZE], &mut [u8; SIZE]),
{
    assert_eq!(input.len(), output.len());
    assert_eq!(input.len() % SIZE, 0);

    let (mut offset, length) = (0_usize, input.len());
    while offset < length {
        // SAFETY: We have either 0 or >= SIZE bytes remaining.
        let (input_arr, output_arr) = unsafe {(
            &*(input as *const [u8] as *const [u8; SIZE]),
            &mut *(output as *mut [u8] as *mut [u8; SIZE]),
        )};

        callback(input_arr, output_arr);
        offset += SIZE;
    }

    debug_assert_eq!(offset, length);
}


pub struct BlowfishContext(UnsafeCell<mbedtls_blowfish_context>);

impl Drop for BlowfishContext {
    fn drop(&mut self) {
        unsafe { mbedtls_blowfish_free(self.ctx_ptr()) }
    }
}

impl BlowfishContext {
    #[inline(always)] unsafe fn ctx_ptr(&self) -> *mut mbedtls_blowfish_context { self.0.get() }

    pub fn new() -> Self {
        let mut context = Default::default();
        unsafe { mbedtls_blowfish_init(&mut context) };
        Self(UnsafeCell::new(context))
    }

    pub fn reset(&mut self) {
        unsafe {
            mbedtls_blowfish_free(self.ctx_ptr());
            mbedtls_blowfish_init(self.ctx_ptr());
        }
    }

    pub fn set_key(&mut self, v: &BlowfishKey) {
        let (data, bits) = (v.data(), v.bits());
        let ret = unsafe { mbedtls_blowfish_setkey(self.ctx_ptr(), data, bits) };
        assert_eq!(ret, 0);
    }

    pub fn decrypt_ecb(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) {
        let (input, output) = (input.as_ptr(), output.as_mut_ptr());
        let ret = unsafe { mbedtls_blowfish_crypt_ecb(self.ctx_ptr(), MODE_DECRYPT, input, output) };
        assert_eq!(ret, 0);
    }

    pub fn encrypt_ecb(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) {
        let (input, output) = (input.as_ptr(), output.as_mut_ptr());
        let ret = unsafe { mbedtls_blowfish_crypt_ecb(self.ctx_ptr(), MODE_ENCRYPT, input, output) };
        assert_eq!(ret, 0);
    }

    pub fn decrypt_ecb_slice(&self, input: &[u8], output: &mut [u8]) {
        for_each_block(input, output, |i, o| self.decrypt_ecb(i, o))
    }

    pub fn encrypt_ecb_slice(&self, input: &[u8], output: &mut [u8]) {
        for_each_block(input, output, |i, o| self.encrypt_ecb(i, o))
    }

    #[inline(always)]
    fn crypt_cbc_internal(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8], mode: i32) {
        assert_eq!(input.len(), output.len());
        assert_eq!(input.len() % BLOCK_SIZE, 0);

        let (length, iv) = (input.len(), iv.as_mut_ptr());
        let (input, output) = (input.as_ptr(), output.as_mut_ptr());

        debug_assert!(mode == MODE_ENCRYPT || mode == MODE_DECRYPT);
        let ret = unsafe { mbedtls_blowfish_crypt_cbc(self.ctx_ptr(), mode, length, iv, input, output) };
        assert_eq!(ret, 0);
    }

    pub fn decrypt_cbc(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
        self.crypt_cbc_internal(iv, input, output, MODE_DECRYPT)
    }

    pub fn encrypt_cbc(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
        self.crypt_cbc_internal(iv, input, output, MODE_ENCRYPT)
    }

    pub fn decrypt_cbc_slice(&self, mut iv: [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
        self.crypt_cbc_internal(&mut iv, input, output, MODE_DECRYPT)
    }

    pub fn encrypt_cbc_slice(&self, mut iv: [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) {
        self.crypt_cbc_internal(&mut iv, input, output, MODE_ENCRYPT)
    }

}

impl Default for BlowfishContext {
    fn default() -> Self {
        Self::new()
    }
}
