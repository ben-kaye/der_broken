use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono;
use dotenv::dotenv;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode as jwt_encode};
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::Display;
use tracing::{Level, debug, error};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug)]
struct Config {
    private_der: &'static str,
    public_der: &'static str,
    private_der_b64: &'static str,
    public_der_b64: &'static str,
    jwt_private_env: &'static str,
    jwt_public_env: &'static str,
}

impl Config {
    const DEFAULT: Self = Self {
        private_der: "private.der",
        public_der: "public.der",
        private_der_b64: "private.der.b64",
        public_der_b64: "public.der.b64",
        jwt_private_env: "JWT_PRIVATE",
        jwt_public_env: "JWT_PUBLIC",
    };
}

trait LoadDer {
    fn load(&self) -> Result<Keys, AuthError>;
}

struct FileDerLoader;
struct B64FileDerLoader;
struct EnvB64DerLoader;

impl LoadDer for FileDerLoader {
    fn load(&self) -> Result<Keys, AuthError> {
        let private_key =
            std::fs::read(Config::DEFAULT.private_der).map_err(AuthError::FileReadError)?;
        let public_key =
            std::fs::read(Config::DEFAULT.public_der).map_err(AuthError::FileReadError)?;
        Ok(Keys::from_der(&private_key, &public_key))
    }
}

impl LoadDer for B64FileDerLoader {
    fn load(&self) -> Result<Keys, AuthError> {
        let private_key = b64file_to_bytes(Config::DEFAULT.private_der_b64)
            .map_err(AuthError::Base64DecodeError)?;
        let public_key = b64file_to_bytes(Config::DEFAULT.public_der_b64)
            .map_err(AuthError::Base64DecodeError)?;
        Ok(Keys::from_der(&private_key, &public_key))
    }
}

impl LoadDer for EnvB64DerLoader {
    fn load(&self) -> Result<Keys, AuthError> {
        dotenv().ok();
        let private_key = env_b64_to_bytes(Config::DEFAULT.jwt_private_env)
            .map_err(|e| AuthError::EnvVarNotFound(e.to_string()))?;
        let public_key = env_b64_to_bytes(Config::DEFAULT.jwt_public_env)
            .map_err(|e| AuthError::EnvVarNotFound(e.to_string()))?;
        Ok(Keys::from_der(&private_key, &public_key))
    }
}

fn b64file_to_bytes(path: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let b64 = std::fs::read_to_string(path).unwrap();
    BASE64.decode(b64.trim())
}

fn env_b64_to_bytes(env_var: &str) -> Result<Vec<u8>, env::VarError> {
    let b64 = env::var(env_var)?;
    Ok(BASE64.decode(b64.trim()).unwrap())
}

fn test_keys(keys: &Keys) -> Result<String, AuthError> {
    let header = Header::new(Algorithm::RS256);
    let claims = Claims {
        sub: "test@domain.com".to_owned(),
        iss: "main.rs".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize,
    };
    jwt_encode(&header, &claims, &keys.encoding).map_err(|err| {
        error!("Error during JWT creation: {:?}", err);
        AuthError::TokenCreation
    })
}

fn main() {
    // Initialize tracing with debug level
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(true)
        .with_thread_names(false)
        .with_ansi(true)
        .with_level(true)
        .with_writer(std::io::stdout)
        .pretty()
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Test FileDerLoader
    debug!("Testing FileDerLoader...");
    match FileDerLoader.load() {
        Ok(keys) => match test_keys(&keys) {
            Ok(token) => debug!("FileDerLoader works! Token: {}", token),
            Err(err) => debug!("FileDerLoader failed to create token: {:?}", err),
        },
        Err(err) => error!("FileDerLoader failed to load keys: {:?}", err),
    }

    // Test B64FileDerLoader
    debug!("Testing B64FileDerLoader...");
    match B64FileDerLoader.load() {
        Ok(keys) => match test_keys(&keys) {
            Ok(token) => debug!("B64FileDerLoader works! Token: {}", token),
            Err(err) => debug!("B64FileDerLoader failed to create token: {:?}", err),
        },
        Err(err) => error!("B64FileDerLoader failed to load keys: {:?}", err),
    }

    // Test EnvB64DerLoader
    debug!("Testing EnvB64DerLoader...");
    match EnvB64DerLoader.load() {
        Ok(keys) => match test_keys(&keys) {
            Ok(token) => debug!("EnvB64DerLoader works! Token: {}", token),
            Err(err) => debug!("EnvB64DerLoader failed to create token: {:?}", err),
        },
        Err(err) => error!("EnvB64DerLoader failed to load keys: {:?}", err),
    }
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.iss)
    }
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn from_der(private_key: &[u8], public_key: &[u8]) -> Self {
        let encoding = EncodingKey::from_rsa_der(private_key);
        let decoding = DecodingKey::from_rsa_der(public_key);

        Self { encoding, decoding }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
}

#[derive(Debug)]
enum AuthError {
    TokenCreation,
    FileReadError(std::io::Error),
    Base64DecodeError(base64::DecodeError),
    EnvVarNotFound(String),
}
