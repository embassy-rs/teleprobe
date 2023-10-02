use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::probe::ProbeSpecifier;

fn default_default_timeout() -> u64 {
    10
}
fn default_max_timeout() -> u64 {
    60
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub targets: Vec<Target>,
    pub auths: Vec<Auth>,
    #[serde(default = "default_default_timeout")]
    pub default_timeout: u64,
    #[serde(default = "default_max_timeout")]
    pub max_timeout: u64,
}

#[derive(Clone, Deserialize)]
pub enum Auth {
    #[serde(rename = "oidc")]
    Oidc(OidcAuth),
    #[serde(rename = "token")]
    Token(TokenAuth),
}

impl ToString for Auth {
    fn to_string(&self) -> String {
        match self {
            Auth::Oidc(_) => "OIDC",
            Auth::Token(_) => "Token",
        }
        .to_string()
    }
}

#[derive(Clone, Deserialize)]
pub struct OidcAuth {
    pub issuer: String,
    pub rules: Vec<OidcAuthRule>,
}

#[derive(Clone, Deserialize)]
pub struct OidcAuthRule {
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

#[derive(Clone, Deserialize)]
pub struct TokenAuth {
    pub token: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Target {
    pub name: String,
    pub chip: String,
    pub probe: ProbeSpecifier,
    #[serde(default)]
    pub connect_under_reset: bool,
    #[serde(default)]
    pub speed: Option<u32>,
    #[serde(default)]
    pub power_reset: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TargetList {
    pub targets: Vec<Target>,
}
