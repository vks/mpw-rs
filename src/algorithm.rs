extern crate crypto;
extern crate byteorder;

use std::io::{Read, Write};
use std::convert::TryInto;

use self::crypto::scrypt::{scrypt, ScryptParams};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::byteorder::{BigEndian, WriteBytesExt};

lazy_static! {
    static ref scrypt_params: ScryptParams = ScryptParams::new(15, 8, 2);
}

/// Represent which variant of password to generate.
#[derive(Clone, Copy)]
enum SiteVariant {
    /// Generate the password to login with.
    Password,
    /// Generate the login name to log in as.
    Login,
    /// Generate the answer to a security question.
    Answer,
}

/// Represent a password variant as a string.
fn scope_for_variant(variant: SiteVariant) -> &'static str {
    match variant {
        SiteVariant::Password => "com.lyndir.masterpassword",
        SiteVariant::Login => "com.lyndir.masterpassword.login",
        SiteVariant::Answer => "com.lyndir.masterpassword.answer",
    }
}

/// Derive a master key from a full name and a master password.
pub fn master_key_for_user_v3(full_name: &[u8], master_password: &[u8]) -> Vec<u8> {
    let mut master_key_salt = Vec::new();
    master_key_salt.write_all(scope_for_variant(SiteVariant::Password).as_bytes());
    let master_key_salt_len = full_name.len().try_into().unwrap();
    // TODO little or big endian?
    master_key_salt.write_u32::<BigEndian>(master_key_salt_len).unwrap();
    master_key_salt.write_all(full_name).unwrap();
    assert!(!master_key_salt.is_empty());
    println!("master key salt: {}", id_for_buf(&master_key_salt));

    let mut master_key = vec![0; 64];
    scrypt(master_password, &master_key_salt, &scrypt_params, &mut master_key);
    println!("master key: {}", id_for_buf(&master_key));

    master_key
}

/// Calculate a hex-encoded ID using SHA256.
pub fn id_for_buf(buf: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.input(buf);
    let hex = hasher.result_str();
    hex
}

#[test]
fn test_key_for_user_v3() {
    let full_name = "John Doe";
    let master_password = "password";
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    let expected_master_key: [u8; 64] = [27, 177, 181, 88, 106, 115, 177, 174, 150, 213, 214, 9,
    53, 44, 141, 132, 20, 254, 89, 228, 224, 58, 95, 52, 226, 174, 130, 64, 244, 84, 216, 6, 136,
    210, 95, 208, 201, 115, 81, 48, 112, 177, 183, 129, 50, 44, 115, 10, 86, 114, 44, 225, 160,
    170, 250, 210, 194, 87, 12, 220, 20, 36, 120, 232];
    assert_eq!(&master_key[..], &expected_master_key as &[u8]);
}
