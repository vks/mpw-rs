//! This implements the Maser Password algorithm.
//! See http://masterpasswordapp.com/algorithm.html.

extern crate conv;
extern crate ring;
extern crate ring_pwhash;
extern crate data_encoding;
extern crate byteorder;

use std::convert::{TryInto, TryFrom};
use std::cmp::max;
use std::io;
use std::io::Write;
use std::error::Error as StdError;
use std::fmt;

use self::ring::{aead, digest, hmac, rand};
use self::ring::rand::{SecureRandom, SystemRandom};
use self::ring_pwhash::scrypt::{scrypt, ScryptParams};
use self::data_encoding::hex;
use self::byteorder::{BigEndian, WriteBytesExt};
use self::conv::ValueInto;

use clear_on_drop::ClearOnDrop;

lazy_static! {
    /// Scrypt parameters used by the Master Password algorithm.
    static ref SCRYPT_PARAMS: ScryptParams = ScryptParams::new(15, 8, 2);
}

/// Represent which variant of password to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteVariant {
    /// Generate the password to login with.
    Password,
    /// Generate the login name to log in as.
    Login,
    /// Generate the answer to a security question.
    Answer,
}

impl SiteVariant {
    /// Try to construct a SiteVariant from a string.
    ///
    /// Returns None if the string does not correspond to a variant.
    pub fn from_str(s: &str) -> Option<SiteVariant> {
        match s {
            "p" | "password"
                => Some(SiteVariant::Password),
            "l" | "login"
                => Some(SiteVariant::Login),
            "a" | "answer"
                => Some(SiteVariant::Answer),
            _ => None,
        }
    }
}

impl ::serde::Serialize for SiteVariant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ::serde::Serializer
    {
        serializer.serialize_str(match *self {
            SiteVariant::Password => "password",
            SiteVariant::Login => "login",
            SiteVariant::Answer => "answer",
        })
    }
}

impl<'de> ::serde::Deserialize<'de> for SiteVariant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: ::serde::Deserializer<'de>
    {
        struct Visitor;

        impl<'de> ::serde::de::Visitor<'de> for Visitor {
            type Value = SiteVariant;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, r#"one of the following strings: "p", "password", "l", "login", "a", "answer""#)
            }

            fn visit_str<E>(self, value: &str) -> Result<SiteVariant, E>
                where E: ::serde::de::Error
            {
                SiteVariant::from_str(value)
                    .ok_or_else(|| E::invalid_value(::serde::de::Unexpected::Str(value), &self))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Type of the site password.
pub enum SiteType {
    GeneratedMaximum,
    GeneratedLong,
    GeneratedMedium,
    GeneratedBasic,
    GeneratedShort,
    GeneratedPIN,
    GeneratedName,
    GeneratedPhrase,
    Stored,
}

impl SiteType {
    /// Try to construct a SiteType from a string.
    ///
    /// Returns None if the string does not correspond to a variant.
    pub fn from_str(s: &str) -> Option<SiteType> {
        match s {
            "x" | "max" | "maximum"
                => Some(SiteType::GeneratedMaximum),
            "l" | "long"
                => Some(SiteType::GeneratedLong),
            "m" | "med" | "medium"
                => Some(SiteType::GeneratedMedium),
            "b" | "basic"
                => Some(SiteType::GeneratedBasic),
            "s" | "short"
                => Some(SiteType::GeneratedShort),
            "i" | "pin"
                => Some(SiteType::GeneratedPIN),
            "n" | "name"
                => Some(SiteType::GeneratedName),
            "p" | "phrase"
                => Some(SiteType::GeneratedPhrase),
            "stored"
                => Some(SiteType::Stored),
            _ => None,
        }
    }
}

impl ::serde::Serialize for SiteType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ::serde::Serializer
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
            SiteType::Stored => "stored",
        })
    }
}

impl<'de> ::serde::Deserialize<'de> for SiteType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: ::serde::Deserializer<'de>
    {
        struct Visitor;

        impl<'de> ::serde::de::Visitor<'de> for Visitor {
            type Value = SiteType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, r#"one of the following strings: "x", "max", "maximum", "l", "long", "m", "med", "medium", "b", "basic", "s", "short", "i", "pin", "n", "name", "p", "phrase", "stored""#)
            }

            fn visit_str<E>(self, value: &str) -> Result<SiteType, E>
                where E: ::serde::de::Error
            {
                SiteType::from_str(value)
                    .ok_or_else(|| E::invalid_value(::serde::de::Unexpected::Str(value), &self))
            }
        }

        deserializer.deserialize_str(Visitor)
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

/// Master Password algorithm kind of error.
#[derive(Debug, Clone, Copy)]
pub enum ErrorKind {
    /// An `std::io::Error` occured.
    Io,
    /// The full name was longer than 2^32 bytes.
    FullNameTooLong,
    /// The site name was longer than 2^32 bytes.
    SiteNameTooLong,
    /// The site context was longer than 2^32 bytes.
    SiteContextTooLong,
}

/// Master Password algorithm error.
#[derive(Debug)]
pub struct Error {
    // TODO: maybe rather use Cow?
    pub message: String,
    pub kind: ErrorKind,
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        let message = match kind {
            ErrorKind::Io => "IO error",
            ErrorKind::FullNameTooLong => "full name too long",
            ErrorKind::SiteNameTooLong => "site name too long",
            ErrorKind::SiteContextTooLong => "site context too long",
        };
        Error { message: message.into(), kind: kind }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error {
            message: e.description().into(),
            kind: ErrorKind::Io,
        }
    }
}

/// Derive a master key from a full name and a master password.
pub fn master_key_for_user_v3(full_name: &[u8], master_password: &[u8])
    -> Result<ClearOnDrop<[u8; 64]>, Error>
{
    let mut master_key_salt = Vec::new();
    master_key_salt.write_all(scope_for_variant(SiteVariant::Password).as_bytes())?;
    let master_key_salt_len = full_name.len().try_into().map_err(|_|
        Error::from(ErrorKind::FullNameTooLong))?;
    master_key_salt.write_u32::<BigEndian>(master_key_salt_len)?;
    master_key_salt.write_all(full_name)?;
    assert!(!master_key_salt.is_empty());

    let mut master_key = ClearOnDrop::new([0; 64]);
    scrypt(master_password, &master_key_salt, &SCRYPT_PARAMS, &mut *master_key);

    Ok(master_key)
}

/// Deterministially generate a password for a site.
pub fn password_for_site_v3(master_key: &[u8; 64], site_name: &[u8], site_type: SiteType,
        site_counter: u32, site_variant: SiteVariant, site_context: &[u8])
    -> Result<ClearOnDrop<String>, Error>
{
    let mut site_password_salt = Vec::new();
    let site_scope = scope_for_variant(site_variant).as_bytes();
    site_password_salt.write_all(site_scope)?;
    let site_name_len = site_name.len().try_into().map_err(|_|
        Error::from(ErrorKind::SiteNameTooLong))?;
    site_password_salt.write_u32::<BigEndian>(site_name_len)?;
    site_password_salt.write_all(site_name)?;
    site_password_salt.write_u32::<BigEndian>(site_counter)?;
    if !site_context.is_empty() {
        let site_context_len = site_context.len().try_into().map_err(|_|
            Error::from(ErrorKind::SiteContextTooLong))?;
        site_password_salt.write_u32::<BigEndian>(site_context_len)?;
        site_password_salt.write_all(site_context)?;
    }
    debug_assert!(!site_password_salt.is_empty());

    let signing_key = hmac::SigningKey::new(&digest::SHA256, master_key);
    let digest = hmac::sign(&signing_key, &site_password_salt);
    let site_password_seed = digest.as_ref();
    debug_assert!(!site_password_seed.is_empty());

    // Encode the password from the seed using the template.
    let site_password = generate_password(site_type, &site_password_seed);

    Ok(site_password)
}

/// Generate a password for the given site type from a given seed.
fn generate_password(site_type: SiteType, seed: &[u8]) -> ClearOnDrop<String> {
    let template = template_for_type(site_type, seed[0]);
    if template.len() >= seed.len() {
        panic!(format!("template too long for given password seed: {} >= {}",
                       template.len(), seed.len()));
    }
    let mut password = ClearOnDrop::new(String::with_capacity(template.len()));
    for (i, c) in template.chars().enumerate() {
        password.push(
            character_from_class(c, seed[i + 1])
        );
    }

    password
}

/// Generate a random password for the given site type.
pub fn random_password_for_site(rng: &SystemRandom, site_type: SiteType) -> Result<ClearOnDrop<String>, ()> {
    let mut seed = ClearOnDrop::new(vec![0; 21]);
    rng.fill(seed.as_mut()).map_err(|_| ())?;
    Ok(generate_password(site_type, &seed))
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
        SiteType::Stored
            => panic!("Expected generated type"),
    }
}

/// Return an internal string that contains the password encoding template of the given type.
fn template_for_type(ty: SiteType, seed_byte: u8) -> &'static str {
    let templates = templates_for_type(ty);
    let count = u8::try_from(templates.len()).unwrap();
    //^ This unwrap is safe, because the templates are hardcoded and much shorter than 256
    //  characters.
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

/// Calculate the bits of entropy of a given template.
fn entropy_of_template(template: &str) -> f64 {
    let mut bits = 0.;
    for class in template.chars() {
        let possibilities: f64 = characters_in_class(class).len().value_into()
            .expect("failed to convert `usize` to `f64`");
        bits += possibilities.log2();
    }
    bits
}

/// Return a character from given character class that encodes the given byte.
fn character_from_class(class: char, seed_byte: u8) -> char {
    let class_chars = characters_in_class(class);
    let index = usize::from(seed_byte % u8::try_from(class_chars.len()).unwrap());
    class_chars.chars().nth(index).unwrap()
    //^ These unwraps are save, because the character classes are hardcoded and shorter than 256
    //  characters.
}

/// Encode a fingerprint for a buffer.
pub fn id_for_buf(buf: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, buf);
    hex::encode(digest.as_ref())
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

    let signing_key = hmac::SigningKey::new(&digest::SHA256, master_password);
    let digest = hmac::sign(&signing_key, full_name);
    let identicon_seed = digest.as_ref();

    // TODO color

    let get_part = |set: &[&'static str], seed: u8| {
        set[usize::from(seed % u8::try_from(set.len()).unwrap())]
        //^ This unwrap is safe, because the sets are short and hardcoded above.
    };
    let mut identicon = String::with_capacity(256);
    identicon.push_str(get_part(&left_arm[..], identicon_seed[0]));
    identicon.push_str(get_part(&body[..], identicon_seed[1]));
    identicon.push_str(get_part(&right_arm[..], identicon_seed[2]));
    identicon.push_str(get_part(&accessory[..], identicon_seed[3]));
    identicon
}

/// Length of the nonce of the used encryption algorithm (chacha20).
const NONCE_LEN: usize = 12;
/// Length to which short passwords are padded before encryption.
///
/// This is chosen to be the same length as the longest generated password.
/// Note that this has to be smaller than 256 due to how he padding is done.
const PAD_LEN: usize = 20;

/// Calculate the length of the clear text after padding.
fn padded_len(clear_text_len: usize) -> usize {
    max(clear_text_len + 1, PAD_LEN)
}

/// Calculate the minimal length of the encryption buffer.
pub fn min_buffer_len(clear_text_len: usize) -> usize {
    padded_len(clear_text_len) + NONCE_LEN + aead::MAX_TAG_LEN
}

/// Pad the password of length `len` to a minimal length `PAD_LEN`.
///
/// Panics if the buffer is too short.
///
/// This is to avoid making it possible to gain information on the length of
/// short passwords.
fn pad(buf: &mut [u8], len: usize) {
    let make_message = |need, got|
        format!("padding buffer too short: need {}, got {}", need, got);
    assert!(buf.len() >= PAD_LEN, make_message(PAD_LEN, buf.len()));
    assert!(buf.len() >= len + 1, make_message(len + 1, buf.len()));
    let padding_byte = if len >= PAD_LEN { 0 } else { (PAD_LEN - len).try_into().unwrap() };
    //^ This unwrap is safe, because `PAD_LEN` is small.
    for b in &mut buf[len..] {
        *b = padding_byte;
    }
}

/// Remove the padding from a password.
///
/// This is the inverse of `pad`.
fn unpad(buf: &[u8]) -> &[u8] {
    let padding_byte = buf[buf.len() - 1];
    let padding_size = usize::from(padding_byte);
    for byte in &buf[buf.len() - padding_size..] {
        debug_assert_eq!(*byte, padding_byte);
    }
    if padding_byte != 0 {
        &buf[0..buf.len() - padding_size]
    } else {
        &buf[0..buf.len() - 1]
    }
}

/// Encrypt data using the master key.
///
/// This is not specified by the Master Password algorithm.
pub fn encrypt(clear_text: &[u8], master_key: &[u8; 64], buffer: &mut [u8]) {
    assert!(buffer.len() >= min_buffer_len(clear_text.len()));

    {
        let (mut nonce, mut rest) = buffer.split_at_mut(NONCE_LEN);

        let rng = rand::SystemRandom::new();
        rng.fill(nonce).expect("failed to generate random nonce");

        {
            let (mut input, _) = rest.split_at_mut(clear_text.len());
            input.clone_from_slice(clear_text);
        }

        // Pad short passwords so their length cannot be guessed by looking
        // at the cipher text.
        let (mut input, _) = rest.split_at_mut(padded_len(clear_text.len()));
        pad(&mut input, clear_text.len());
    }

    let key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &master_key[0..32])
        .expect("invalid CHACHA20_POLY1305 key");
    let (nonce, mut in_out) = buffer.split_at_mut(NONCE_LEN);
    aead::seal_in_place(&key, nonce, &[], in_out, aead::MAX_TAG_LEN)
        .expect("failed to encrypt password");
}

/// Decrypt data using the master key.
/// Decryption is in-place, a slice to the decrypted clear text is returned.
///
/// This is not specified by the Master Password algorithm.
pub fn decrypt<'a>(master_key: &[u8; 64], buffer: &'a mut [u8]) -> &'a [u8] {
    let key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &master_key[0..32])
        .expect("invalid CHACHA20_POLY1305 key");
    assert!(buffer.len() > NONCE_LEN, "invalid cipher text");
    let (nonce, mut in_out) = buffer.split_at_mut(NONCE_LEN);
    let padded = aead::open_in_place(&key, nonce, &[], 0, in_out)
        .expect("failed to decrypt password");
    unpad(padded)
}

#[test]
fn test_key_for_user_v3() {
    let full_name = "John Doe";
    let master_password = "password";
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    ).unwrap();
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
fn test_template_entropy() {
    use SiteType::*;

    /// Calculate minimal bits of entropy.
    // TODO: Figure out how to calculate actual entropy
    fn bits(ty: SiteType) -> f64 {
        let mut min = ::std::f64::INFINITY;
        for t in &templates_for_type(ty) {
            min = entropy_of_template(*t).min(min);
        }
        min
    }

    assert!(bits(GeneratedMaximum) > 118.4);
    assert!(bits(GeneratedLong) > 48.1);
    assert!(bits(GeneratedMedium) > 30.1);
    assert!(bits(GeneratedBasic) > 38.4);
    assert!(bits(GeneratedShort) > 14.4);
    assert!(bits(GeneratedPIN) > 13.2);
    assert!(bits(GeneratedName) > 31.2);
    assert!(bits(GeneratedPhrase) > 55.7);
}

#[test]
fn test_password_for_site_v3() {
    let full_name = "John Doe";
    let master_password = "password";
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    ).unwrap();
    let site_name = "google.com";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    ).unwrap();
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
    ).unwrap();
    let site_name = "de.wikipedia.org";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    ).unwrap();
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
    ).unwrap();
    let site_name = "山东大学.cn";
    let password = password_for_site_v3(
        &master_key, site_name.as_bytes(), SiteType::GeneratedLong, 1,
        SiteVariant::Password, &[]
    ).unwrap();
    assert_eq!(*password, "ZajmGabl0~Zoza");
}

#[test]
fn test_padding_short() {
    let mut vec = vec![1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    pad(&mut vec, 5);
    assert_eq!(&vec,
        &[1, 2, 3, 4, 5, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]);
    assert_eq!(unpad(&vec), &[1, 2, 3, 4, 5]);
}

#[test]
fn test_padding_long() {
    for &len in &[PAD_LEN, PAD_LEN + 1] {
        let mut vec = vec![100; len + 1];
        pad(&mut vec, len);
        let mut expected = vec![100; len + 1];
        expected[len] = 0;
        assert_eq!(&vec, &expected);
        assert_eq!(unpad(&vec), &vec![100; len][..]);
    }
}

#[test]
fn test_encryption() {
    let clear_text = b"This is a secret.";
    let key = [1; 64];
    let mut buffer = vec![0; min_buffer_len(clear_text.len())];
    encrypt(clear_text, &key, &mut buffer);
    let decrypted = decrypt(&key, &mut buffer);
    assert_eq!(clear_text, decrypted);
}
