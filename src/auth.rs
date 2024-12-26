use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // User ID
    pub exp: usize,
    // TODO(miguel): remove later - 2024/12/22
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityToken {
    pub sub: String, // User ID
    // fields
    pub name: Option<String>,
    pub email: String,
    pub picture: Option<String>, // Expiration timestamp
}
