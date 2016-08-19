extern crate toml;
extern crate serde;

use std::borrow::{Cow, Borrow};

use algorithm::{SiteType, SiteVariant};


/// Represent the configuration state that can be stored on disk.
#[derive(Serialize, Debug)]
pub struct Config<'a> {
    pub full_name: Option<Cow<'a, str>>,
    pub sites: Option<Vec<SiteConfig<'a>>>,
}

impl<'a> Config<'a> {
    /// Create a new empty configuration.
    pub fn new() -> Config<'a> {
        Config { full_name: None, sites: None }
    }

    /// Create a configuration given a TOML string.
    pub fn from_str(s: &'a str) -> Config<'a> {
        unimplemented!()
    }

    /// Encode the config as a TOML string.
    pub fn encode(&self) -> String {
        toml::encode_str(self)
    }
}

/// The configuration that can be stored about a site.
#[derive(Serialize, Debug, Clone)]
pub struct SiteConfig<'a> {
    pub name: Cow<'a, str>,
    #[serde(rename = "type")]
    pub type_: Option<SiteType>,
    pub counter: Option<u32>,
    pub variant: Option<SiteVariant>,
    pub context: Option<Cow<'a, str>>,
}

impl<'a> SiteConfig<'a> {
    /// Create a new site configuration with the given domain name.
    pub fn new(name: &'a str) -> SiteConfig<'a> {
        SiteConfig {
            name: name.into(),
            type_: None,
            counter: None,
            variant: None,
            context: None,
        }
    }
}

/// The configuration state of a site with all default values plugged in.
#[derive(Debug, Clone)]
pub struct Site<'a> {
    pub name: Cow<'a, str>,
    pub type_: SiteType,
    pub counter: u32,
    pub variant: SiteVariant,
    pub context: Cow<'a, str>,
}

impl<'a> Site<'a> {
    /// Create a site from a given config. Missing values are filled with defaults.
    pub fn from_config(config: &'a SiteConfig<'a>) -> Site<'a> {
        let variant = config.variant.unwrap_or(SiteVariant::Password);
        let type_ = config.type_.unwrap_or(
            match variant {
                SiteVariant::Password => SiteType::GeneratedLong,
                SiteVariant::Login => SiteType::GeneratedName,
                SiteVariant::Answer => SiteType::GeneratedPhrase,
            }
        );
        let context = match config.context {
            Some(ref s) => s.as_ref().into(),
            None => "".into(),
        };

        Site {
            name: config.name.as_ref().into(),
            type_: type_,
            counter: config.counter.unwrap_or(1),
            variant: variant,
            context: context,
        }
    }
}

#[test]
fn test_config_encode() {
    let mut c = Config::new();
    assert_eq!(c.encode(), "");
    c.full_name = Some("John Doe".into());
    assert_eq!(c.encode(), "full_name = \"John Doe\"\n");

    let wikipedia = SiteConfig::new("wikipedia.org");
    c.sites = Some(vec![wikipedia]);
    assert_eq!(c.encode(),
r#"full_name = "John Doe"

[[sites]]
name = "wikipedia.org"
"#);

    let mut github = SiteConfig::new("github.com");
    github.type_ = Some(SiteType::GeneratedMaximum);
    github.counter = Some(1);
    github.variant = Some(SiteVariant::Password);
    github.context = Some("".into());
    let bitbucket = SiteConfig::new("bitbucket.org");
    c.sites = Some(vec![github, bitbucket]);
    assert_eq!(c.encode(),
r#"full_name = "John Doe"

[[sites]]
context = ""
counter = 1
name = "github.com"
type = "maximum"
variant = "password"

[[sites]]
name = "bitbucket.org"
"#);
}

#[test]
fn test_variant_encode() {
    #[derive(Debug, Serialize)]
    struct V { variant: SiteVariant }
    assert_eq!(toml::encode_str(&V { variant: SiteVariant::Password }),
               "variant = \"password\"\n");
}

#[test]
fn test_type_encode() {
    #[derive(Debug, Serialize)]
    struct T { type_: SiteType }
    assert_eq!(toml::encode_str(&T { type_: SiteType::GeneratedLong }),
               "type_ = \"long\"\n");
}

#[test]
fn test_config_decode() {
    let config_str = r#"full_name = "John Doe"

[[sites]]
name = "github.com"
type = "maximum"
"#;
}
