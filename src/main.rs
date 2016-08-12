#![feature(try_from)]

#[macro_use]
extern crate lazy_static;

extern crate clap;

use clap::{Arg, App};

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
             .takes_value(true))
        .arg(Arg::with_name("variant")
             .short("v")
             .help("The kind of content to generate")
             .takes_value(true)
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
}
