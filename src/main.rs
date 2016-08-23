#![feature(try_from, custom_derive, plugin, question_mark)]
#![plugin(serde_macros)]

#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate rpassword;
extern crate serde;

use std::io::{Read, Write};
use std::fs::File;

use clap::{Arg, App};
use rpassword::read_password;

mod algorithm;
use algorithm::*;
mod clear_on_drop;
mod config;
use config::*;

static TYPE_HELP: &'static str =
"The password's template{n}\
(defaults to 'long' for password, 'name' for login, 'phrase' for answer){n}\
{n}\
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
        .arg(Arg::with_name("site")
             .help("The domain name of the site.")
             .required(true)
             .number_of_values(1)
             .index(1))
        .arg(Arg::with_name("full name")
             .long("name")
             .short("u")
             .help("The full name of the user. Optional if given in config.")
             .required_unless("config")
             .number_of_values(1)
             .takes_value(true))
        .arg(Arg::with_name("type")
             .long("type")
             .short("t")
             .help(TYPE_HELP)
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
             .long("counter")
             .short("c")
             .help("The value of the site counter.")
             .takes_value(true)
             .number_of_values(1))
        .arg(Arg::with_name("variant")
             .long("variant")
             .short("v")
             .help("The kind of content to generate.")
             .takes_value(true)
             .number_of_values(1)
             .possible_values(&[
                "p", "password",
                "l", "login",
                "a", "answer"
             ]))
        .arg(Arg::with_name("context")
             .long("context")
             .short("C")
             .help("Empty for a universal site or the most significant word(s) of the question.")
             .takes_value(true)
             .number_of_values(1))
        .arg(Arg::with_name("dump")
             .long("dump")
             .short("d")
             .help("Dump the configuration as a TOML file."))
        .arg(Arg::with_name("config")
             .long("config")
             .short("f")
             .help("Read configuration from a TOML file.")
             .takes_value(true)
             .number_of_values(1))
        .get_matches();

    // If given, read config from path.
    let config_path = matches.value_of("config");
    let mut config_string = String::new();
    let mut config = if let Some(path) = config_path {
        let mut f = File::open(path)
            .expect("could not open given config file");
        f.read_to_string(&mut config_string)
            .expect("could not read given config file");
        Config::from_str(&config_string)
            .expect("could not parse given config file")
    } else {
        Config::new()
    };

    let mut param_config = Config::new();
    param_config.full_name = matches.value_of("full name").map(Into::into);
    let param_site_config = SiteConfig {
        name: matches.value_of("site").unwrap().into(),
        //^ required, thus present
        type_: matches.value_of("type").map(|s| SiteType::from_str(s).unwrap()),
        counter: matches.value_of("counter")
        .map(|c| c.parse().expect("counter must be an unsigned 32-bit integer")),
        variant: matches.value_of("variant").map(|s| SiteVariant::from_str(s).unwrap()),
        context: matches.value_of("context").map(Into::into),
    };
    param_config.sites = Some(vec![param_site_config]);

    config.merge(param_config);

    let dump_config = matches.is_present("dump");

    print!("Please enter the master password: ");
    std::io::stdout().flush().unwrap();  // Flush to make sure the prompt is visible.
    let master_password = read_password().expect("could not read password");

    let full_name = config.full_name.as_ref().unwrap();
    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    println!("Identicon: {}", identicon);
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );

    for site_config in config.sites.as_ref().unwrap().iter() {
        let site = Site::from_config(site_config);
        let generated_password = password_for_site_v3(
            &master_key,
            site.name.as_bytes(),
            site.type_,
            site.counter,
            site.variant,
            site.context.as_bytes()
        );
        println!("Password for {}: {}", site.name, *generated_password);
    }

    if dump_config {
        let s = config.encode();
        assert!(s != "");
        println!("config:\n```\n{}```", s);
    }
}
