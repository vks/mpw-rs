#![feature(try_from)]

#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate rpassword;

use std::io::Write;

use clap::{Arg, App};
use rpassword::read_password;

mod algorithm;
use algorithm::*;

static TYPE_HELP: &'static str =
"The password's template (defaults to 'long' for password, 'name' for login)

x, max, maximum   20 characters, contains symbols.{n}\
l, long           Copy-friendly, 14 characters, contains symbols.{n}\
m, med, medium    Copy-friendly, 8 characters, contains symbols.{n}\
b, basic          8 characters, no symbols.{n}\
s, short          Copy-friendly, 4 characters, no symbols.{n}\
i, pin            4 numbers.{n}\
n, name           9 letter name.{n}\
p, phrase         20 character sentence.";

fn main() {
    let matches = App::new("Master Password")
        .about("A stateless password management solution.")
        .arg(Arg::with_name("full name")
             .short("u")
             .help("The full name of the user")
             .takes_value(true))
        .arg(Arg::with_name("type")
             .short("t")
             .help(TYPE_HELP)
             .next_line_help(true)
             .takes_value(true)
             .number_of_values(1)
             .possible_values(&[
                 "x", "max", "maximum",
                 "l", "long",
                 "m", "med", "medium",
                 "b", "basic",
                 "s", "short",
                 "i", "pin",
                 "n", "name",
                 "p", "phrase",
             ]))
        .arg(Arg::with_name("counter")
             .short("c")
             .help("The value of the site counter")
             .takes_value(true)
             .number_of_values(1))
        .arg(Arg::with_name("variant")
             .short("v")
             .help("The kind of content to generate")
             .takes_value(true)
             .number_of_values(1)
             .possible_values(&[
                "p", "password",
                "l", "login",
                "a", "answer"
             ]))
        .arg(Arg::with_name("context")
             .short("C")
             .help("Empty for a universal site or the most significant word(s) of the question")
             .takes_value(true))
        .get_matches();

    let full_name = matches.value_of("full name").unwrap_or("");

    let site_type = matches.value_of("type").map(|s| match s {
        "x" | "max" | "maximum"
            => SiteType::GeneratedMaximum,
        "l" | "long"
            => SiteType::GeneratedLong,
        "m" | "med" | "medium"
            => SiteType::GeneratedMedium,
        "b" | "basic"
            => SiteType::GeneratedBasic,
        "s" | "short"
            => SiteType::GeneratedShort,
        "i" | "pin"
            => SiteType::GeneratedPIN,
        "n" | "name"
            => SiteType::GeneratedName,
        "p" | "phrase"
            => SiteType::GeneratedPhrase,
        _ => panic!("invalid password type"),
    }).unwrap_or(SiteType::GeneratedLong);

    let counter: u32 = matches.value_of("counter")
        .map(|c| c.parse().expect("counter must be an unsigned 32-bit integer"))
        .unwrap_or(1);

    let variant = matches.value_of("variant").map(|s| match s {
        "p" | "password"
            => SiteVariant::Password,
        "l" | "login"
            => SiteVariant::Login,
        "a" | "answer"
            => SiteVariant::Answer,
        _ => panic!("invalid site variant"),
    }).unwrap_or(SiteVariant::Password);

    let context = matches.value_of("context").unwrap_or("");

    print!("Please enter the master password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().expect("could not read password");

    let identicon = identicon(full_name.as_bytes(), password.as_bytes());
    println!("Identicon: {}", identicon);
    let master_key = master_key_for_user_v3(full_name.as_bytes(), password.as_bytes());
    let sitename = "";
    let generated_password = password_for_site_v3(
        &master_key, sitename.as_bytes(), site_type, counter, variant, context.as_bytes());
    println!("Derived password: {}", generated_password);
}
