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
mod clear_on_drop;
mod config;

use algorithm::{SiteVariant, SiteType, master_key_for_user_v3,
    password_for_site_v3, identicon, min_buffer_len, encrypt, decrypt};
use clear_on_drop::ClearOnDrop;
use config::{merge_options, Config, SiteConfig, Site};

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

/// Flush to make sure the prompt is visible.
fn flush() {
    std::io::stdout().flush().unwrap_or_exit("could not flush stdout");
}

/// Read the master password from stdin and generate the master key.
fn generate_master_key(full_name: &str) -> ClearOnDrop<[u8; 64]> {
    print!("Please enter the master password: ");
    flush();
    let master_password = read_password().unwrap_or_exit("could not read master password");

    let identicon = identicon(full_name.as_bytes(), master_password.as_bytes());
    println!("Identicon: {}", identicon);
    let master_key = master_key_for_user_v3(
        full_name.as_bytes(),
        master_password.as_bytes()
    ).unwrap_or_exit("could not generate master key");
    master_key
}

/// Read a site password to be stored from stdin.
fn get_site_password() -> ClearOnDrop<String> {
    print!("Please enter the site password to be stored: ");
    flush();
    let password = read_password().unwrap_or_exit("could not read site password");
    ClearOnDrop::new(password)
}

/// Exit the program with an error message.
fn exit(message: &str) -> ! {
    let err = clap::Error::with_description(message, clap::ErrorKind::InvalidValue);
    // Ther ErrorKind does not really matter, because we are only interested in exiting and
    // creating a nice error message in case of failure.
    err.exit()
}

trait UnwrapOrExit<T>
    where Self: Sized
{
    /// Unwrap the value or execute a closure.
    fn unwrap_or_else<F>(self, f: F) -> T
        where F: FnOnce() -> T;

    /// Unwrap the value or exit the program with an error message.
    fn unwrap_or_exit(self, message: &str) -> T {
        self.unwrap_or_else(|| exit(message))
    }
}

impl<T> UnwrapOrExit<T> for Option<T> {
    fn unwrap_or_else<F>(self, f: F) -> T
        where F: FnOnce() -> T
    {
        self.unwrap_or_else(f)
    }
}

impl<T, E> UnwrapOrExit<T> for Result<T, E> {
    fn unwrap_or_else<F>(self, f: F) -> T
        where F: FnOnce() -> T
    {
        self.unwrap_or_else(|_| f())
    }
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
             .short("i")
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
             .help("Replace parameters of all site passwords in configuration file.{n}\
                    Does not delete stored passwords.")
             .requires_all(&["site", "config"])
             .conflicts_with_all(&["add", "delete", "store"]))
        .arg(Arg::with_name("delete")
             .long("delete")
             .short("D")
             .help("Delete parameters of all site passwords in configuration file.{n}\
                    Does not delete stored passwords.")
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
            .unwrap_or_exit("could not open given config file");
        f.read_to_string(&mut config_string)
            .unwrap_or_exit("could not read given config file");
        Config::from_str(&config_string)
            .unwrap_or_exit("could not parse given config file")
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
            //^ This unwrap is safe, because clap already did the check.
            counter: matches.value_of("counter")
            .map(|c| c.parse().unwrap_or_exit("counter must be an unsigned 32-bit integer")),
            variant: matches.value_of("variant").map(|s| SiteVariant::from_str(s).unwrap()),
            //^ This unwrap is safe, because clap already did the check.
            context: matches.value_of("context").map(Into::into),
            encrypted: None,
        };
        param_config.sites = Some(vec![param_site_config]);
    }

    if matches.is_present("replace") || matches.is_present("delete") {
        // Remove all sites that have the given name, unless they stored a
        // password.
        let param_site_name = param_site_name.unwrap();
        //^ This unwrap is safe, because clap already did the check.
        if let Some(ref mut sites) = config.sites {
            sites.retain(|ref s|
                s.name != param_site_name || s.encrypted.is_some());
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
            if config_name != param_name {
               exit("full name given as paramater conflicts with config");
            }
        }
        if matches.is_present("store") {
            let full_name = merge_options(
                config.full_name.as_ref(),
                param_config.full_name.as_ref(),
            ).unwrap_or_exit("need full name to generate master key");
            let key = generate_master_key(full_name);

            let password = get_site_password();
            let mut buffer = vec![0; min_buffer_len(password.len())];
            encrypt(password.as_ref(), &key, &mut buffer);
            let ref mut site = param_config.sites.as_mut().unwrap()[0];
            //^ This unwrap is safe, because we now it was set to Some before.
            site.encrypted = Some(
                base64::encode(&buffer).into()
            );
            site.type_ = Some(SiteType::Stored);
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
        debug_assert!(s != "");
        let path = config_path.as_ref().unwrap();
        //^ This unwrap is safe, because clap already did the check.
        let mut f = File::create(path)
            .unwrap_or_exit("could not overwrite given config file");
        f.write_all(s.as_bytes())
            .unwrap_or_exit("could not write to given config file");
        return;
    }

    if matches.is_present("dump") {
        // Output config.
        let s = config.encode();
        debug_assert!(s != "");
        println!("{}", s);
        return;
    }

    let full_name = config.full_name.as_ref()
        .unwrap_or_exit("need full name to generate master key");

    let site_configs = config.sites.as_ref()
        .unwrap_or_exit("need a site via command line parameters or via config");

    let master_key = if let Some(key) = master_key {
        key
    } else {
        generate_master_key(full_name)
    };

    // Generate or decrypt passwords.
    for site_config in site_configs {
        let site = Site::from_config(site_config).unwrap_or_else(|e| exit(&e.message));
        // If a site was given, skip all other sites.
        // FIXME: site from parameter should not be printed if already present?
        if let Some(name) = param_site_name {
            if name != site.name {
                continue;
            }
        }
        // We have to define the containers of the passwords here, so that the
        // slices into them survive until we print the password.
        let mut buffer = ClearOnDrop::new(vec![]);
        let password_string;
        let password = match site.type_ {
            SiteType::Stored => {
                let encrypted = site.encrypted.as_ref()
                    .unwrap_or_exit("found stored password without 'encrypted' field")
                    .as_bytes();
                let decoded = &base64::decode(encrypted)
                    .unwrap_or_exit("could not decode 'encrypted' field");
                buffer.resize(decoded.len(), 0);
                buffer.clone_from_slice(decoded);
                let decrypted = decrypt(&master_key, &mut buffer);
                std::str::from_utf8(decrypted).unwrap_or_exit("could not decrypt stored password")
            },
            _ => {
                password_string = password_for_site_v3(
                    &master_key,
                    site.name.as_bytes(),
                    site.type_,
                    site.counter,
                    site.variant,
                    site.context.as_bytes()
                ).unwrap_or_exit("could not generate site password");
                &password_string
            },
        };
        // TODO: print non-default parameters
        println!("Password for {}: {}", site.name, password);
    }
}
