use std::collections::HashMap;

use anyhow::{anyhow, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::RwLock;

#[derive(Clone, Deserialize)]
struct OpenIDConfiguration {
    issuer: String,
    jwks_uri: String,
    subject_types_supported: Vec<String>,
    claims_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[derive(Clone, Deserialize)]
struct JsonWebKey {
    kty: String,
    kid: String,
    alg: Algorithm,

    n: String,
    e: String,
}

struct Issuer {
    config: OpenIDConfiguration,
    keys: JsonWebKeySet,
}

pub struct Client {
    issuers: RwLock<HashMap<String, Issuer>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            issuers: RwLock::new(HashMap::new()),
        }
    }

    async fn discover_issuer(&self, issuer: &str) -> anyhow::Result<Issuer> {
        let mut config_url = issuer.to_string();
        if !config_url.ends_with('/') {
            config_url.push('/');
        }
        config_url.push_str(".well-known/openid-configuration");
        let config: OpenIDConfiguration = reqwest::get(config_url).await?.json().await?;
        let keys: JsonWebKeySet = reqwest::get(&config.jwks_uri).await?.json().await?;

        Ok(Issuer { config, keys })
    }

    async fn ensure_discover_issuer(&self, issuer: &str) -> anyhow::Result<()> {
        if self.issuers.read().await.contains_key(issuer) {
            return Ok(());
        }

        let iss = self.discover_issuer(issuer).await?;
        self.issuers.write().await.insert(issuer.to_string(), iss);

        Ok(())
    }

    pub async fn validate_token<T>(&self, token: &str, issuer: &str) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        self.ensure_discover_issuer(issuer).await?;
        let issuers = self.issuers.read().await;
        let iss = issuers.get(issuer).unwrap();

        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow!("header.kid empty"))?;

        let key = iss
            .keys
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| anyhow!("key with kid {} not found in set", kid))?;

        if key.alg != header.alg {
            bail!("Key alg mismatch");
        }

        match header.alg {
            Algorithm::RS256 => {
                let mut validation = Validation::new(key.alg);
                validation.iss = Some(iss.config.issuer.clone());
                let key = DecodingKey::from_rsa_components(&key.n, &key.e);
                let decoded = jsonwebtoken::decode::<T>(token, &key, &validation)?;
                Ok(decoded.claims)
            }
            alg => bail!("Unsupported algo {:?}", alg),
        }
    }
}
