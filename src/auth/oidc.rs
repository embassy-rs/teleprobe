use anyhow::{anyhow, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::Deserialize;

mod base64 {
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes()).map_err(serde::de::Error::custom)
    }
}

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

#[derive(Clone)]
pub struct Client {
    oidc_config: OpenIDConfiguration,
    keys: JsonWebKeySet,
}

impl Client {
    pub async fn new_autodiscover(issuer: &str) -> anyhow::Result<Self> {
        let mut config_url = issuer.to_string();
        if !config_url.ends_with('/') {
            config_url.push('/');
        }
        config_url.push_str(".well-known/openid-configuration");
        let oidc_config: OpenIDConfiguration = reqwest::get(config_url).await?.json().await?;
        let keys: JsonWebKeySet = reqwest::get(&oidc_config.jwks_uri).await?.json().await?;

        Ok(Self { oidc_config, keys })
    }

    pub fn validate_token<T>(&self, token: &str) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow!("header.kid empty"))?;

        let key = self
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
                validation.set_issuer(&[&self.oidc_config.issuer]);
                let key = DecodingKey::from_rsa_components(&key.n, &key.e).unwrap();
                let decoded = jsonwebtoken::decode::<T>(token, &key, &validation)?;
                Ok(decoded.claims)
            }
            alg => bail!("Unsupported algo {:?}", alg),
        }
    }
}
