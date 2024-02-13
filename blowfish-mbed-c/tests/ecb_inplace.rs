//! Tests vectors by Eric Young. Published by Bruce Schneier.
//! See: https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt

use blowfish_mbed_c::{BlowfishContext, BlowfishKey};


macro_rules! check_ecb_enc {
    ($key:literal, $cleartext:literal, $ciphertext:literal) => {
        {
            let key = BlowfishKey::new(&utils::str_to_vec($key)).unwrap();
            let ctx = BlowfishContext::with_key(&key).unwrap();
            let mut buf = utils::str_to_block($cleartext);
            ctx.encrypt_ecb_inplace(&mut buf).unwrap();
            assert_eq!(&buf, &utils::str_to_block($ciphertext));
        }
    };
}

macro_rules! check_ecb_dec {
    ($key:literal, $cleartext:literal, $ciphertext:literal) => {
        {
            let key = BlowfishKey::new(&utils::str_to_vec($key)).unwrap();
            let ctx = BlowfishContext::with_key(&key).unwrap();
            let mut buf = utils::str_to_block($ciphertext);
            ctx.decrypt_ecb_inplace(&mut buf).unwrap();
            assert_eq!(&buf, &utils::str_to_block($cleartext));
        }
    };
}


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


mod utils {
    use blowfish_mbed_c::BLOCK_SIZE;

    pub fn str_to_vec(s: &str) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(s.len() / 2 + 1);
        (0 .. s.len()).step_by(2)
            .map(|o| u8::from_str_radix(&s[o .. o + 2], 16).unwrap())
            .for_each(|byte| buffer.push(byte));
        buffer
    }

    pub fn str_to_block(block: &str) -> [u8; BLOCK_SIZE] {
        str_to_vec(block).try_into().unwrap()
    }
}
