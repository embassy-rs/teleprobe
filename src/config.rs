use anyhow::anyhow;
use serde::{de, Deserialize, Deserializer};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Config {
    pub targets: Vec<Target>,
    pub auth: Auth,
}

#[derive(Deserialize)]
pub struct Auth {
    pub issuer: String,
    pub rules: Vec<AuthRule>,
}

#[derive(Deserialize)]
pub struct AuthRule {
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct Target {
    pub name: String,
    pub chip: String,
    pub probe: String,
}

pub struct ProbeFilter {
    pub vid_pid: Option<(u16, u16)>,
    pub serial: Option<String>,
}

impl<'de> Deserialize<'de> for ProbeFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl FromStr for ProbeFilter {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split(':').collect::<Vec<_>>();
        match &*parts {
            [serial] => Ok(Self {
                vid_pid: None,
                serial: Some(serial.to_string()),
            }),
            [vid, pid] => Ok(Self {
                vid_pid: Some((u16::from_str_radix(vid, 16)?, u16::from_str_radix(pid, 16)?)),
                serial: None,
            }),
            [vid, pid, serial] => Ok(Self {
                vid_pid: Some((u16::from_str_radix(vid, 16)?, u16::from_str_radix(pid, 16)?)),
                serial: Some(serial.to_string()),
            }),
            _ => Err(anyhow!("invalid probe filter")),
        }
    }
}
