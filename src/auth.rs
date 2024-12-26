use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct LoginData {
    pub redirect: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthData {
    pub code: Option<String>,
    pub error: Option<String>,
    pub state: Option<String>,
}

#[derive(Serialize)]
pub struct TokenForm {
    pub code: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub grant_type: String,
}

#[derive(Deserialize, Debug)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
}

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
