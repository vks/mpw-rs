#![feature(try_from, custom_derive, plugin, question_mark, core_intrinsics)]
#![plugin(serde_macros)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate clap;
extern crate rpassword;
extern crate serde;
extern crate data_encoding;

use std::io::{Read, Write};
use std::fs::File;

use clap::{Arg, App, AppSettings};
use rpassword::read_password;
use data_encoding::base64;

mod algorithm;
use algorithm::*;
mod clear_on_drop;
use clear_on_drop::ClearOnDrop;
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
p, phrase         20 character sentence.{n}";

fn generate_master_key(full_name: &str) -> ClearOnDrop<[u8; 64]> {
    print!("Please enter the master password: ");
    std::io::stdout().flush().unwrap();  // Flush to make sure the prompt is visible.
    let master_password = read_password().expect("could not read master password");

    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    println!("Identicon: {}", identicon);
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    );
    master_key
}

fn get_site_password() -> ClearOnDrop<String> {
    print!("Please enter the site password to be stored: ");
    std::io::stdout().flush().unwrap();  // Flush to make sure the prompt is visible.
    let password = read_password().expect("could not read site password");
    ClearOnDrop::new(password)
}

fn main() {
    let matches = App::new("Master Password")
        .about("A stateless password management solution.")
        .version(crate_version!())
        .setting(AppSettings::HidePossibleValuesInHelp)
        .arg(Arg::with_name("site")
             .help("The domain name of the site.")
             .number_of_values(1)
             .index(1)
             .required_unless("config"))
        .arg(Arg::with_name("full name")
             .long("name")
             .short("u")
             .help("The full name of the user.{n}Optional if given in config.")
             .required_unless("config")
             .number_of_values(1)
             .takes_value(true))
        .arg(Arg::with_name("type")
             .long("type")
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
             .long("counter")
             .short("c")
             .help("The value of the site counter.")
             .takes_value(true)
             .number_of_values(1))
        .arg(Arg::with_name("variant")
             .long("variant")
             .short("v")
             .help("The kind of content to generate (defaults to 'password'){n}\
                    {n}\
                    p, password  Generate a password{n}\
                    l, login     Generate a login name{n}\
                    a, answer    Generate an answer to a question")
             .next_line_help(true)
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
             .help("Dump the configuration as a TOML."))
        .arg(Arg::with_name("config")
             .long("config")
             .short("f")
             .help("Read configuration from a TOML file.")
             .takes_value(true)
             .number_of_values(1))
        .arg(Arg::with_name("add")
             .long("add")
             .short("a")
             .help("Add parameters of site password to configuration file.")
             .requires_all(&["site", "config"])
             .conflicts_with_all(&["replace", "delete", "store"]))
        .arg(Arg::with_name("replace")
             .long("replace")
             .short("r")
             .help("Replace parameters of all site passwords in configuration file.")
             .requires_all(&["site", "config"])
             .conflicts_with_all(&["add", "delete", "store"]))
        .arg(Arg::with_name("delete")
             .long("delete")
             .short("D")
             .help("Delete parameters of all site passwords in configuration file.")
             .requires_all(&["site", "config"])
             .conflicts_with_all(&["add", "replace", "store"]))
        .arg(Arg::with_name("store")
             .long("store")
             .short("s")
             .help("Encrypt and store a password")
             .requires_all(&["site", "config"])
             .conflicts_with_all(&["add", "delete", "replace"]))
        .set_term_width(0)
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

    // Read config from CLI parameters.
    let mut param_config = Config::new();
    param_config.full_name = matches.value_of("full name").map(Into::into);
    let param_site_name = matches.value_of("site");
    if let Some(name) = param_site_name {
        let param_site_config = SiteConfig {
            name: name.into(),
            type_: matches.value_of("type").map(|s| SiteType::from_str(s).unwrap()),
            counter: matches.value_of("counter")
            .map(|c| c.parse().expect("counter must be an unsigned 32-bit integer")),
            variant: matches.value_of("variant").map(|s| SiteVariant::from_str(s).unwrap()),
            context: matches.value_of("context").map(Into::into),
            encrypted: None,
        };
        param_config.sites = Some(vec![param_site_config]);
    }

    if matches.is_present("replace") || matches.is_present("delete") {
        // Remove all sites that have the given name.
        let param_site_name = param_site_name.unwrap();
        if let Some(ref mut sites) = config.sites {
            sites.retain(|ref s| s.name != param_site_name);
        }
    }

    let mut master_key = None;
    if matches.is_present("add") ||
       matches.is_present("replace") ||
       matches.is_present("store") ||
       !matches.is_present("config") {
        // Merge parameters into config.
        if let (Some(config_name), Some(param_name)) =
            (config.full_name.as_ref(), param_config.full_name.as_ref())
        {
            assert_eq!(config_name, param_name);
        }
        if matches.is_present("store") {
            let full_name = merge_options(
                config.full_name.as_ref(),
                param_config.full_name.as_ref(),
            ).expect("need full name to generate master key");
            let key = generate_master_key(full_name);

            let password = get_site_password();
            let mut buffer = vec![0; min_buffer_len(password.len())];
            encrypt(password.as_ref(), &key, &mut buffer);
            param_config.sites.as_mut().unwrap()[0].encrypted = Some(
                base64::encode(&buffer).into()
            );
            master_key = Some(key);
        }
        config.merge(param_config);
    }

    if matches.is_present("add") ||
       matches.is_present("replace") ||
       matches.is_present("delete") ||
       matches.is_present("store") {
        // Overwrite config file.
        let s = config.encode();
        assert!(s != "");
        let path = config_path.as_ref().unwrap();  // Clap checked it is present.
        let mut f = File::create(path)
            .expect("could not overwrite given config file");
        f.write_all(s.as_bytes())
            .expect("could not write to given config file");
        return;
    }

    if matches.is_present("dump") {
        // Output config.
        let s = config.encode();
        assert!(s != "");
        println!("{}", s);
        return;
    }

    let full_name = config.full_name.as_ref()
        .expect("need full name to generate master key");

    let master_key = if let Some(key) = master_key { key } else { generate_master_key(full_name) };

    // Generate or decrypt passwords.
    for site_config in config.sites.as_ref().unwrap().iter() {
        let site = Site::from_config(site_config);
        // If a site was given, skip all other sites.
        // FIXME: site from parameter should not be printed if already present?
        if let Some(name) = param_site_name {
            if name != site.name {
                continue;
            }
        }
        let password = match site.type_ {
            SiteType::StoredPersonal | SiteType::StoredDevicePrivate => {
                unimplemented!()
            },
            _ => {
                password_for_site_v3(
                    &master_key,
                    site.name.as_bytes(),
                    site.type_,
                    site.counter,
                    site.variant,
                    site.context.as_bytes()
                )
            },
        };
        // TODO: print non-default parameters
        println!("Password for {}: {}", site.name, *password);
    }
}
