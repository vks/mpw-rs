extern crate crypto;
extern crate byteorder;
extern crate serde;

use std::io::Write;
use std::convert::{TryInto, TryFrom};

use self::crypto::scrypt::{scrypt, ScryptParams};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::crypto::hmac::Hmac;
use self::crypto::mac::Mac;
use self::byteorder::{BigEndian, WriteBytesExt};

use clear_on_drop::ClearOnDrop;

lazy_static! {
    static ref SCRYPT_PARAMS: ScryptParams = ScryptParams::new(15, 8, 2);
}

/// Represent which variant of password to generate.
#[derive(Clone, Copy, Debug)]
pub enum SiteVariant {
    /// Generate the password to login with.
    Password,
    /// Generate the login name to log in as.
    Login,
    /// Generate the answer to a security question.
    Answer,
}

impl serde::Serialize for SiteVariant {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer 
    {
        serializer.serialize_str(match *self {
            SiteVariant::Password => "password",
            SiteVariant::Login => "login",
            SiteVariant::Answer => "answer",
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SiteType {
    GeneratedMaximum,
    GeneratedLong,
    GeneratedMedium,
    GeneratedBasic,
    GeneratedShort,
    GeneratedPIN,
    GeneratedName,
    GeneratedPhrase,
    StoredPersonal,
    StoredDevicePrivate,
}

impl serde::Serialize for SiteType {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
        serializer.serialize_str(match *self {
            SiteType::GeneratedMaximum => "maximum",
            SiteType::GeneratedLong => "long",
            SiteType::GeneratedMedium => "medium",
            SiteType::GeneratedBasic => "basic",
            SiteType::GeneratedShort => "short",
            SiteType::GeneratedPIN => "pin",
            SiteType::GeneratedName => "name",
            SiteType::GeneratedPhrase => "phrase",
            _ => unimplemented!(),
        })
    }
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
pub fn master_key_for_user_v3(full_name: &[u8], master_password: &[u8]) -> ClearOnDrop<[u8; 64]> {
    let mut master_key_salt = Vec::new();
    master_key_salt.write_all(scope_for_variant(SiteVariant::Password).as_bytes()).unwrap();
    let master_key_salt_len = full_name.len().try_into().unwrap();
    master_key_salt.write_u32::<BigEndian>(master_key_salt_len).unwrap();
    master_key_salt.write_all(full_name).unwrap();
    assert!(!master_key_salt.is_empty());

    let mut master_key = ClearOnDrop::new([0; 64]);
    scrypt(master_password, &master_key_salt, &SCRYPT_PARAMS, &mut master_key.container);

    master_key
}

pub fn password_for_site_v3(master_key: &[u8; 64], site_name: &[u8], site_type: SiteType,
        site_counter: u32, site_variant: SiteVariant, site_context: &[u8]) -> ClearOnDrop<String> {
    let mut site_password_salt = Vec::new();
    let site_scope = scope_for_variant(site_variant).as_bytes();
    site_password_salt.write_all(site_scope).unwrap();
    let site_name_len = site_name.len().try_into().unwrap();
    site_password_salt.write_u32::<BigEndian>(site_name_len).unwrap();
    site_password_salt.write_all(site_name).unwrap();
    site_password_salt.write_u32::<BigEndian>(site_counter).unwrap();
    if !site_context.is_empty() {
        let site_context_len = site_context.len().try_into().unwrap();
        site_password_salt.write_u32::<BigEndian>(site_context_len).unwrap();
        site_password_salt.write_all(site_context).unwrap();
    }
    assert!(!site_password_salt.is_empty());

    let mut hmac = Hmac::new(Sha256::new(), master_key);
    hmac.input(&site_password_salt);
    let mut site_password_seed = [0u8; 32];
    hmac.raw_result(&mut site_password_seed);
    assert!(!site_password_seed.is_empty());

    let template = template_for_type(site_type, site_password_seed[0]);
    if template.len() > 32 {
        panic!("Template to long for password seed");
    }

    // Encode the password from the seed using the template.
    let mut site_password = ClearOnDrop::new(String::new());
    for i in 0..template.len() {
        let c = template.chars().nth(i).unwrap();
        site_password.container.push(
            character_from_class(c, site_password_seed[i + 1])
        );
    }

    site_password
}

/// Return an array of internal strings that express the template to use for the given type.
fn templates_for_type(ty: SiteType) -> Vec<&'static str> {
    match ty {
        SiteType::GeneratedMaximum => vec![
            "anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"
        ],
        SiteType::GeneratedLong => vec![
            "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
            "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
            "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
            "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc",
            "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc",
            "CvccCvcvCvccno"
        ],
        SiteType::GeneratedMedium => vec![
            "CvcnoCvc", "CvcCvcno"
        ],
        SiteType::GeneratedBasic => vec![
            "aaanaaan", "aannaaan", "aaannaaa"
        ],
        SiteType::GeneratedShort => vec![
            "Cvcn",
        ],
        SiteType::GeneratedPIN => vec![
            "nnnn",
        ],
        SiteType::GeneratedName => vec![
            "cvccvcvcv",
        ],
        SiteType::GeneratedPhrase => vec![
            "cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv",
        ],
        SiteType::StoredPersonal | SiteType::StoredDevicePrivate
            => panic!("Expected generated type"),
    }
}

/// Return an internal string that contains the password encoding template of the given type.
fn template_for_type(ty: SiteType, seed_byte: u8) -> &'static str {
    let templates = templates_for_type(ty);
    let count = u8::try_from(templates.len()).unwrap();
    templates[usize::from(seed_byte % count)]
}

/// Return an internal string that contains all the characters occuring in the given class.
///
/// - 'V': uppercase vowel
/// - 'C': uppercase consonant
/// - 'v': lowercase vowel
/// - 'c': lowercase consonant
/// - 'A': upper case letter
/// - 'a': letter (any case)
/// - 'n': digit
/// - 'o': special symbol
/// - 'x': letter (any case) or digit or special symbol
fn characters_in_class(class: char) -> &'static str {
    match class {
        'V' => "AEIOU",
        'C' => "BCDFGHJKLMNPQRSTVWXYZ",
        'v' => "aeiou",
        'c' => "bcdfghjklmnpqrstvwxyz",
        'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
        'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
        'n' => "0123456789",
        'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
        'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        ' ' => " ",
        _ => panic!("Unknown character class"),
    }
}

/// Return a character from given character class that encodes the given byte.
fn character_from_class(class: char, seed_byte: u8) -> char {
    let class_chars = characters_in_class(class);
    let index = usize::from(seed_byte % u8::try_from(class_chars.len()).unwrap());
    class_chars.chars().nth(index).unwrap()
}

/// Encode a fingerprint for a buffer.
pub fn id_for_buf(buf: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.input(buf);
    let hex = hasher.result_str();
    hex
}

/// Encode a visual fingerprint for a user.
pub fn identicon(full_name: &[u8], master_password: &[u8]) -> String {
    let left_arm = [ "╔", "╚", "╰", "═" ];
    let right_arm = [ "╗", "╝", "╯", "═" ];
    let body = [ "█", "░", "▒", "▓", "☺", "☻" ];
    let accessory = [
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎",
        "☏", "⎈", "⌂", "☘", "☢", "☣", "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔",
        "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟", "♨", "♩",
        "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌"
    ];

    let mut hmac = Hmac::new(Sha256::new(), master_password);
    hmac.input(full_name);

    let mut identicon_seed = [0; 32];
    hmac.raw_result(&mut identicon_seed);

    // TODO color

    let get_part = |set: &[&'static str], seed: u8| {
        set[usize::from(seed % u8::try_from(set.len()).unwrap())]
    };
    let mut identicon = String::with_capacity(256);
    identicon.push_str(get_part(&left_arm[..], identicon_seed[0]));
    identicon.push_str(get_part(&body[..], identicon_seed[1]));
    identicon.push_str(get_part(&right_arm[..], identicon_seed[2]));
    identicon.push_str(get_part(&accessory[..], identicon_seed[3]));
    identicon
}

#[test]
fn test_key_for_user_v3() {
    let full_name = "John Doe";
    let master_password = "password";
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    let expected_master_key: [u8; 64] = [
        27, 177, 181, 88, 106, 115, 177, 174, 150, 213, 214, 9, 53, 44, 141,
        132, 20, 254, 89, 228, 224, 58, 95, 52, 226, 174, 130, 64, 244, 84, 216,
        6, 136, 210, 95, 208, 201, 115, 81, 48, 112, 177, 183, 129, 50, 44, 115,
        10, 86, 114, 44, 225, 160, 170, 250, 210, 194, 87, 12, 220, 20, 36, 120,
        232
    ];
    assert_eq!(&master_key[..], &expected_master_key[..]);
}

#[test]
fn test_password_for_site_v3() {
    let full_name = "John Doe";
    let master_password = "password";
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    let site_name = "google.com";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    );
    assert_eq!(*password, "QubnJuvaMoke2~");
}

#[test]
fn test_identicon() {
    let full_name = "John Doe";
    let master_password = "password";
    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    assert_eq!(identicon, "╔░╝⌚");
}

#[test]
fn test_unicode_user_name() {
    let full_name = "Max Müller";
    let master_password = "passwort";
    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    assert_eq!(identicon, "═▒╝♚");
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    let site_name = "de.wikipedia.org";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    );
    assert_eq!(*password, "DaknJezb6,Zula");
}

#[test]
fn test_unicode_site_name() {
    let full_name = "Zhang Wei";
    let master_password = "password";
    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    assert_eq!(identicon, "╔░╗◒");
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    let site_name = "山东大学.cn";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    );
    assert_eq!(*password, "ZajmGabl0~Zoza");
}
