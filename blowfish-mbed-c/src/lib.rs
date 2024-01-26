#![allow(dead_code)]
#![allow(unsafe_code)]
#![no_std]

//! Lean and safe interface for Blowfish cipher from the `mbedtls` implementation.
//!
//! This crate provides a rusty wrapper around the `blowfish_mbed_sys` bindings to the Blowfish
//! cipher implementation taken from an older branch of the `mbedtls` library. So far, only
//! ECB, CBC and CFB block cipher modes of operation have been wrapped and tested.

use core::cell::UnsafeCell;
use core::ops::RangeInclusive;
use core::ptr;

use blowfish_mbed_sys::*;
use snafu::prelude::*;


/// Error type for all [`BlowfishContext`] operations.
#[derive(Debug, Clone, Snafu)]
pub enum BlowfishError {
    /// Input and output buffers had different lengths.
    #[snafu(display("input / output length did not match: {input} != {output}"))]
    LengthMismatch { input: usize, output: usize },
    /// Input or output buffer had a length that was not a multiple of the block size.
    #[snafu(display("input / output length was not a multiple of block size: {length}"))]
    LengthNotMultiple { length: usize },
    /// A FFI binding returned an error code even though all error conditions have been checked.
    #[snafu(display("ffi binding returned an unexpected error code: {code}"))]
    Unknown { code: i32 },
}


/// Lowest number of bytes in a valid Blowfish key.
pub const KEY_BYTES_MIN: usize = MBEDTLS_BLOWFISH_MIN_KEY_BITS as usize / 8;
/// Highest number of bytes in a valid Blowfish key.
pub const KEY_BYTES_MAX: usize = MBEDTLS_BLOWFISH_MAX_KEY_BITS as usize / 8;

const KEY_BYTES_RANGE: RangeInclusive<usize> = KEY_BYTES_MIN ..= KEY_BYTES_MAX;


/// Type-safe variable-size Blowfish cipher key.
///
/// Represents a number of bytes between [`KEY_BYTES_MIN`] and [`KEY_BYTES_MAX`] inclusively.
///
/// # Rationale
/// Moving key validation to a separate type, as opposed to providing a byte slice directly to
/// the cryptography functions, effectively lifts a whole category of errors upwards, allowing
/// for a much cleaner interface.
#[derive(Clone, PartialEq, Eq)]
pub struct BlowfishKey {
    bytes: [u8; KEY_BYTES_MAX],
    size: usize,
}

impl BlowfishKey {
    /// Tries to construct a new key from `slice`.
    /// Returns [`None`] if the `slice` is too short or too long.
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

    /// Retrieves the bytes of this key.
    /// The returned slice is guaranteed to have a length valid for a Blowfish key.
    #[inline(always)]
    pub fn slice(&self) -> &[u8] {
        // SAFETY: Keys cannot be constructed with size out of bounds.
        unsafe { self.bytes.get_unchecked(.. self.size) }
    }

    /// Retrieves the bytes of this key as a mutable slice.
    /// The returned slice is guaranteed to have a length valid for a Blowfish key.
    #[inline(always)]
    pub fn slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: Keys cannot be constructed with size out of bounds.
        unsafe { self.bytes.get_unchecked_mut(.. self.size) }
    }

    /// Retrieves the number of bytes in this key.
    #[inline(always)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Retrieves the number of bits in this key.
    #[inline(always)] pub fn bits(&self) -> u32 { self.size as u32 * 8 }
    /// Retrieves a pointer to the bytes of this key.
    #[inline(always)] pub fn data(&self) -> *const u8 { self.slice().as_ptr() }
}


/// Number of bytes in a Blowfish cipher block.
pub const BLOCK_SIZE: usize = MBEDTLS_BLOWFISH_BLOCKSIZE as usize;

const MODE_DECRYPT: i32 = MBEDTLS_BLOWFISH_DECRYPT as i32;
const MODE_ENCRYPT: i32 = MBEDTLS_BLOWFISH_ENCRYPT as i32;

#[inline(always)]
fn for_each_block<const SIZE: usize, CB>(input: &[u8], output: &mut [u8], callback: CB) -> Result<(), BlowfishError>
where
    CB: Fn(&[u8; SIZE], &mut [u8; SIZE]) -> Result<(), BlowfishError>,
{
    ensure!(input.len() == output.len(), LengthMismatchSnafu { input: input.len(), output: output.len() });
    ensure!(input.len() % SIZE == 0, LengthNotMultipleSnafu { length: input.len() });

    let (mut offset, length) = (0_usize, input.len());
    while offset < length {
        // SAFETY: We have either 0 or >= SIZE bytes remaining.
        let (input_arr, output_arr) = unsafe {(
            &*(input as *const [u8] as *const [u8; SIZE]),
            &mut *(output as *mut [u8] as *mut [u8; SIZE]),
        )};

        callback(input_arr, output_arr)?;
        offset += SIZE;
    }
    debug_assert_eq!(offset, length);

    Ok(())
}


/// Blowfish cipher context for decrypting and/or encrypting data.
pub struct BlowfishContext(UnsafeCell<mbedtls_blowfish_context>);

impl Clone for BlowfishContext {
    fn clone(&self) -> Self {
        Self(UnsafeCell::new(unsafe { ptr::read(self.ctx_ptr()) }))
    }
}

impl Drop for BlowfishContext {
    fn drop(&mut self) {
        unsafe { mbedtls_blowfish_free(self.ctx_ptr()) }
    }
}

impl Default for BlowfishContext {
    fn default() -> Self {
        Self::new()
    }
}

impl BlowfishContext {
    #[inline(always)]
    unsafe fn ctx_ptr(&self) -> *mut mbedtls_blowfish_context {
        self.0.get()
    }

    /// Initializes a context without updating the key.
    /// The key must be set prior to any `decrypt_` / `encrypt_` calls.
    pub fn new() -> Self {
        let mut context = Default::default();
        unsafe { mbedtls_blowfish_init(&mut context) };
        Self(UnsafeCell::new(context))
    }

    /// Initializes a context and immediately updates the key.
    pub fn with_key(v: &BlowfishKey) -> Result<Self, BlowfishError> {
        let mut instance = Self::new();
        instance.set_key(v).map(|_| instance)
    }

    /// Reinitializes this context.
    /// Identical to dropping this context and constructing a new one.
    pub fn reset(&mut self) {
        unsafe {
            mbedtls_blowfish_free(self.ctx_ptr());
            mbedtls_blowfish_init(self.ctx_ptr());
        }
    }

    /// Updates the key for this cipher context.
    pub fn set_key(&mut self, v: &BlowfishKey) -> Result<(), BlowfishError> {
        let (data, bits) = (v.data(), v.bits());
        let code = unsafe { mbedtls_blowfish_setkey(self.ctx_ptr(), data, bits) };
        ensure!(code == 0, UnknownSnafu { code });
        Ok(())
    }

    #[inline(always)]
    fn crypt_ecb_internal(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE], mode: i32) -> Result<(), BlowfishError> {
        let (input, output) = (input.as_ptr(), output.as_mut_ptr());

        debug_assert!(mode == MODE_ENCRYPT || mode == MODE_DECRYPT);
        let code = unsafe { mbedtls_blowfish_crypt_ecb(self.ctx_ptr(), mode, input, output) };
        ensure!(code == 0, UnknownSnafu { code });

        Ok(())
    }

    /// Decrypt a single block in the **electronic codebook** (ECB) mode.
    pub fn decrypt_ecb(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) -> Result<(), BlowfishError> {
        self.crypt_ecb_internal(input, output, MODE_DECRYPT)
    }

    /// Encrypt a single block in the **electronic codebook** (ECB) mode.
    pub fn encrypt_ecb(&self, input: &[u8; BLOCK_SIZE], output: &mut [u8; BLOCK_SIZE]) -> Result<(), BlowfishError> {
        self.crypt_ecb_internal(input, output, MODE_ENCRYPT)
    }

    /// Decrypt a number of blocks in the **electronic codebook** (ECB) mode.
    ///
    /// # Arguments
    /// * `input` - Ciphertext bytes, must have a length that is a multiple of the cipher block size (8 bytes).
    /// * `output` - Pre-allocated buffer for cleartext bytes, must be exactly as long as `input`.
    ///
    /// # Returns
    /// This function will return an error if `input` and `output` have different lengths,
    /// or if their length is not a multiple of the cipher block size (8 bytes).
    pub fn decrypt_ecb_slice(&self, input: &[u8], output: &mut [u8]) -> Result<(), BlowfishError> {
        for_each_block(input, output, |i, o| self.decrypt_ecb(i, o))
    }

    /// Encrypt a number of blocks in the **electronic codebook** (ECB) mode.
    ///
    /// # Arguments
    /// * `input` - Cleartext bytes, must have a length that is a multiple of the cipher block size (8 bytes).
    /// * `output` - Pre-allocated buffer for ciphertext bytes, must be exactly as long as `input`.
    ///
    /// # Returns
    /// This function will return an error if `input` and `output` have different lengths,
    /// or if their length is not a multiple of the cipher block size (8 bytes).
    pub fn encrypt_ecb_slice(&self, input: &[u8], output: &mut [u8]) -> Result<(), BlowfishError> {
        for_each_block(input, output, |i, o| self.encrypt_ecb(i, o))
    }

    #[inline(always)]
    fn crypt_cbc_internal(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8], mode: i32) -> Result<(), BlowfishError> {
        ensure!(input.len() == output.len(), LengthMismatchSnafu { input: input.len(), output: output.len() });
        ensure!(input.len() % BLOCK_SIZE == 0, LengthNotMultipleSnafu { length: input.len() });

        let (length, iv) = (input.len(), iv.as_mut_ptr());
        let (input, output) = (input.as_ptr(), output.as_mut_ptr());

        debug_assert!(mode == MODE_ENCRYPT || mode == MODE_DECRYPT);
        let code = unsafe { mbedtls_blowfish_crypt_cbc(self.ctx_ptr(), mode, length, iv, input, output) };
        ensure!(code == 0, UnknownSnafu { code });

        Ok(())
    }

    /// Decrypt a number of blocks in the **cipher block chaining** (CBC) mode.
    ///
    /// # Arguments
    /// * `iv` - Initialization vector, updated by this function. An exclusive reference to the same vector
    ///     may be passed to several invocations of this function in a row to implement "streaming" decryption
    ///     of non-contiguous slices.
    /// * `input` - Ciphertext bytes, must have a length that is a multiple of the cipher block size (8 bytes).
    /// * `output` - Pre-allocated buffer for cleartext bytes, must be exactly as long as `input`.
    ///
    /// # Returns
    /// This function will return an error if `input` and `output` have different lengths,
    /// or if their length is not a multiple of the cipher block size (8 bytes).
    pub fn decrypt_cbc_slice(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) -> Result<(), BlowfishError> {
        self.crypt_cbc_internal(iv, input, output, MODE_DECRYPT)
    }

    /// Encrypt a number of blocks in the **cipher block chaining** (CBC) mode.
    ///
    /// # Arguments
    /// * `iv` - Initialization vector, updated by this function. An exclusive reference to the same vector
    ///     may be passed to several invocations of this function in a row to implement "streaming" encryption
    ///     of non-contiguous slices.
    /// * `input` - Cleartext bytes, must have a length that is a multiple of the cipher block size (8 bytes).
    /// * `output` - Pre-allocated buffer for ciphertext bytes, must be exactly as long as `input`.
    ///
    /// # Returns
    /// This function will return an error if `input` and `output` have different lengths,
    /// or if their length is not a multiple of the cipher block size (8 bytes).
    pub fn encrypt_cbc_slice(&self, iv: &mut [u8; BLOCK_SIZE], input: &[u8], output: &mut [u8]) -> Result<(), BlowfishError> {
        self.crypt_cbc_internal(iv, input, output, MODE_ENCRYPT)
    }
}
