extern crate toml;
extern crate serde;

use self::serde::Serialize;

use algorithm::{SiteType, SiteVariant};

/// Represent the configuration state that can be stored on disk.
#[derive(Serialize, Debug)]
pub struct Config<'a> {
    pub full_name: Option<&'a str>,
    pub sites: Vec<SiteConfig<'a>>,
}

impl<'a> Config<'a> {
    /// Create a new empty configuration.
    pub fn new() -> Config<'a> {
        Config { full_name: None, sites: Vec::new() }
    }

    /// Encode the config as a TOML string.
    fn encode(&self) -> String {
        toml::encode_str(self)
    }
}

/// The configuration that can be stored about a site.
#[derive(Serialize, Debug)]
pub struct SiteConfig<'a> {
    pub name: &'a str,
    pub type_: Option<SiteType>,
    pub counter: Option<u32>,
    pub variant: Option<SiteVariant>,
    pub context: Option<&'a str>,
}

impl<'a> SiteConfig<'a> {
    /// Create a new site configuration with the given domain name.
    pub fn new(name: &'a str) -> SiteConfig<'a> {
        SiteConfig {
            name: name,
            type_: None,
            counter: None,
            variant: None,
            context: None,
        }
    }
}

/// The configuration state of a site with all default values plugged in.
pub struct Site<'a> {
    pub name: &'a str,
    pub type_: SiteType,
    pub counter: u32,
    pub variant: SiteVariant,
    pub context: &'a str,
}

impl<'a> Site<'a> {
    /// Create a site from a given config. Missing values are filled with defaults.
    pub fn from_config(config: SiteConfig<'a>) -> Site<'a> {
        Site {
            name: config.name,
            type_: config.type_.unwrap_or(SiteType::GeneratedLong),
            counter: config.counter.unwrap_or(1),
            variant: config.variant.unwrap_or(SiteVariant::Password),
            context: config.context.unwrap_or(""),
        }
    }
}

#[test]
fn test_config_encode() {
    let c = Config::new();
    assert_eq!(c.encode(), "");
}
