extern crate toml;

use std::borrow::Cow;

use algorithm::{SiteType, SiteVariant};


/// Merge two options, prefering Some and the new one.
pub fn merge_options<T>(old: Option<T>, new: Option<T>) -> Option<T> {
    match (old.is_some(), new.is_some()) {
        (true, true) => new,
        (true, false) => old,
        (false, true) => new,
        (false, false) => None,
    }
}

/// Represent the configuration state that can be stored on disk.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Config<'a> {
    pub full_name: Option<Cow<'a, str>>,
    pub sites: Option<Vec<SiteConfig<'a>>>,
}

impl<'a> Config<'a> {
    /// Create a new empty configuration.
    pub fn new() -> Config<'a> {
        Config { full_name: None, sites: None }
    }

    /// Try to create a configuration given a TOML string.
    pub fn from_str(s: &'a str) -> Option<Config<'a>> {
        toml::decode_str(s)
    }

    /// Encode the config as a TOML string.
    pub fn encode(&self) -> String {
        toml::encode_str(self)
    }

    /// Merge another configuration into this one.
    ///
    /// Values from the other configuration are prefered unless None.
    pub fn merge(&mut self, other: Config<'a>) {
        if other.full_name.is_some() {
            self.full_name = other.full_name;
        }
        if let Some(other_sites) = other.sites {
            if let Some(ref mut sites) = self.sites {
                sites.extend(other_sites);
            } else {
                self.sites = Some(other_sites);
            }
        }
    }
}

/// The configuration that can be stored about a site.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SiteConfig<'a> {
    pub name: Cow<'a, str>,
    #[serde(rename = "type")]
    pub type_: Option<SiteType>,
    pub counter: Option<u32>,
    pub variant: Option<SiteVariant>,
    pub context: Option<Cow<'a, str>>,
    pub encrypted: Option<Cow<'a, str>>,
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
            encrypted: None,
        }
    }

    /// Merge another configuration into this one.
    ///
    /// Values from the other configuration are prefered unless None.
    /// Panics if the configurations are not for the same website.
    pub fn merge(&mut self, other: SiteConfig<'a>) {
        assert_eq!(self.name, other.name,
                   "can only merge configs for the same site");
        self.type_ = merge_options(self.type_, other.type_);
        self.counter = merge_options(self.counter, other.counter);
        self.variant = merge_options(self.variant, other.variant);
        assert!(self.encrypted.is_none() && other.encrypted.is_none());
        if other.context.is_some() {
            self.context = other.context;
        }
    }
}

/// The configuration state of a site with all default values plugged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site<'a> {
    pub name: Cow<'a, str>,
    pub type_: SiteType,
    pub counter: u32,
    pub variant: SiteVariant,
    pub context: Cow<'a, str>,
    pub encrypted: Option<Cow<'a, str>>,
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
        let encrypted = match config.encrypted {
            Some(ref s) => Some(s.as_ref().into()),
            None => None,
        };

        Site {
            name: config.name.as_ref().into(),
            type_: type_,
            counter: config.counter.unwrap_or(1),
            variant: variant,
            context: context,
            encrypted: encrypted,
        }
    }
}

#[test]
fn test_config_merge() {
    let mut c1 = Config::new();
    let mut c2 = Config::new();
    let mut c3 = Config::new();

    let wikipedia = SiteConfig::new("wikipedia.org");
    let github = SiteConfig::new("github.com");
    c2.sites = Some(vec![wikipedia.clone()]);
    c3.sites = Some(vec![github.clone()]);
    c1.merge(c2);
    assert_eq!(c1.sites, Some(vec![wikipedia.clone()]));
    c1.merge(c3);
    assert_eq!(c1.sites, Some(vec![wikipedia, github]));
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
    let config = Config::from_str(config_str).unwrap();

    let mut expected_config = Config::new();
    expected_config.full_name = Some("John Doe".into());
    let mut github = SiteConfig::new("github.com");
    github.type_ = Some(SiteType::GeneratedMaximum);
    expected_config.sites = Some(vec![github]);

    assert_eq!(config, expected_config);
}
