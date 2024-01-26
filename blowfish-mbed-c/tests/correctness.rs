//! Tests vectors by Eric Young. Published by Bruce Schneier.
//! See: https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt

use blowfish_mbed_c::{BlowfishContext, BlowfishKey, BLOCK_SIZE};


macro_rules! check_ecb_enc {
    ($key:literal, $cleartext:literal, $ciphertext:literal) => {
        {
            let key = BlowfishKey::new(&utils::str_to_vec($key)).unwrap();
            let ctx = BlowfishContext::with_key(&key).unwrap();
            let mut ciphertext = [0u8; BLOCK_SIZE];
            ctx.encrypt_ecb(&utils::str_to_block($cleartext), &mut ciphertext).unwrap();
            assert_eq!(&ciphertext, &utils::str_to_block($ciphertext));
        }
    };
}

macro_rules! check_ecb_dec {
    ($key:literal, $cleartext:literal, $ciphertext:literal) => {
        {
            let key = BlowfishKey::new(&utils::str_to_vec($key)).unwrap();
            let ctx = BlowfishContext::with_key(&key).unwrap();
            let mut cleartext = [0u8; BLOCK_SIZE];
            ctx.decrypt_ecb(&utils::str_to_block($ciphertext), &mut cleartext).unwrap();
            assert_eq!(&cleartext, &utils::str_to_block($cleartext));
        }
    };
}


/// Check that single-block **electronic codebook** vectors are correct for encryption.
#[test]
fn test_ecb_encrypt() {
    check_ecb_enc!("0000000000000000", "0000000000000000", "4EF997456198DD78");
    check_ecb_enc!("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A");
    check_ecb_enc!("3000000000000000", "1000000000000001", "7D856F9A613063F2");
    check_ecb_enc!("1111111111111111", "1111111111111111", "2466DD878B963C9D");
    check_ecb_enc!("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096");
    check_ecb_enc!("1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7");
    check_ecb_enc!("0000000000000000", "0000000000000000", "4EF997456198DD78");
    check_ecb_enc!("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D");
    check_ecb_enc!("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B");

    // TODO: Add the remaining vectors.
}

/// Check that single-block **electronic codebook** vectors are correct for decryption.
#[test]
fn test_ecb_decrypt() {
    check_ecb_dec!("0000000000000000", "0000000000000000", "4EF997456198DD78");
    check_ecb_dec!("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A");
    check_ecb_dec!("3000000000000000", "1000000000000001", "7D856F9A613063F2");
    check_ecb_dec!("1111111111111111", "1111111111111111", "2466DD878B963C9D");
    check_ecb_dec!("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096");
    check_ecb_dec!("1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7");
    check_ecb_dec!("0000000000000000", "0000000000000000", "4EF997456198DD78");
    check_ecb_dec!("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D");
    check_ecb_dec!("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B");

    // TODO: Add the remaining vectors.
}

/// Check that the multi-block **cipher block chaining** vector
/// is correct for encryption in a single go.
#[test]
fn test_cbc_encrypt() {
    let key = BlowfishKey::new(&utils::str_to_vec("0123456789ABCDEFF0E1D2C3B4A59687")).unwrap();
    let ctx = BlowfishContext::with_key(&key).unwrap();

    let cleartext = utils::str_to_padded("37363534333231204E6F77206973207468652074696D6520666F722000");
    let ciphertext_exp = utils::str_to_vec("6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC");
    let mut iv = utils::str_to_block("FEDCBA9876543210");

    let mut ciphertext = [0u8; 32];
    ctx.encrypt_cbc_slice(&mut iv, &cleartext, &mut ciphertext).unwrap();
    assert_eq!(&ciphertext, ciphertext_exp.as_slice());
}

/// Check that the multi-block **cipher block chaining** vector
/// is correct for decryption in a single go.
#[test]
fn test_cbc_decrypt() {
    let key = BlowfishKey::new(&utils::str_to_vec("0123456789ABCDEFF0E1D2C3B4A59687")).unwrap();
    let ctx = BlowfishContext::with_key(&key).unwrap();

    let ciphertext = utils::str_to_padded("6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC");
    let cleartext_exp = utils::str_to_vec("37363534333231204E6F77206973207468652074696D6520666F722000");

    let mut iv = utils::str_to_block("FEDCBA9876543210");
    let mut cleartext = [0u8; 32];

    ctx.decrypt_cbc_slice(&mut iv, &ciphertext, &mut cleartext).unwrap();
    assert_eq!(&cleartext[.. cleartext_exp.len()], cleartext_exp.as_slice());
}

/// Check that the multi-block **cipher block chaining** vector
/// is correct for decryption with a "streaming" interface.
#[test]
fn test_cbc_decrypt_stream() {
    let key = BlowfishKey::new(&utils::str_to_vec("0123456789ABCDEFF0E1D2C3B4A59687")).unwrap();
    let ctx = BlowfishContext::with_key(&key).unwrap();

    let ciphertext_parts = [
        utils::str_to_padded("6B77B4D63006DEE6"),
        utils::str_to_padded("05B156E27403979358DEB9E7154616D9"),
        utils::str_to_padded("59F1652BD5FF92CC"),
    ];
    let cleartext_exp = utils::str_to_vec("37363534333231204E6F77206973207468652074696D6520666F722000");

    let mut iv = utils::str_to_block("FEDCBA9876543210");
    let mut cleartext = Vec::with_capacity(32);

    for ciphertext_part in ciphertext_parts {
        let mut cleartext_part = vec![0u8; ciphertext_part.len()];
        ctx.decrypt_cbc_slice(&mut iv, &ciphertext_part, &mut cleartext_part).unwrap();
        cleartext.append(&mut cleartext_part);
    }

    assert_eq!(&cleartext[.. cleartext_exp.len()], cleartext_exp.as_slice());
}


mod utils {
    use blowfish_mbed_c::BLOCK_SIZE;

    pub fn str_to_vec(s: &str) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(s.len() / 2 + 1);
        (0 .. s.len()).step_by(2)
            .map(|o| u8::from_str_radix(&s[o .. o + 2], 16).unwrap())
            .for_each(|byte| buffer.push(byte));
        buffer
    }

    pub fn str_to_padded(s: &str) -> Vec<u8> {
        let mut vec = str_to_vec(s);
        let remaining = vec.len().next_multiple_of(BLOCK_SIZE) - vec.len();
        (0 .. remaining).for_each(|_| vec.push(u8::default()));
        debug_assert_eq!(vec.len() % BLOCK_SIZE, 0);
        vec
    }

    pub fn str_to_block(block: &str) -> [u8; BLOCK_SIZE] {
        str_to_vec(block).try_into().unwrap()
    }
}
