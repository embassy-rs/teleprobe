use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::probe::ProbeSpecifier;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub targets: Vec<Target>,
    pub auths: Vec<Auth>,
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TargetList {
    pub targets: Vec<Target>,
}
