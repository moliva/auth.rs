use std::env;
use std::future::Future;
use std::time::Duration;

use actix_web::{HttpRequest, HttpResponse, Result};
use awc::cookie::{time, Cookie};
use awc::{self, Client};
use google_jwt_verify::{Client as GoogleClient, IdPayload};
use uuid::Uuid;

use crate::auth::{AuthData, Claims, IdentityToken, LoginData, TokenForm, TokenResponse};
use crate::cookies::{cookie, remove_cookie};
use crate::jwt::{generate_access_token, generate_id_token, generate_refresh_token, verify_jwt};

pub async fn auth<T, F, Fut, G, Gut>(
    req: HttpRequest,
    auth_data: AuthData,
    handle_user: F,
    handle_refresh_token: G,
) -> Result<HttpResponse>
where
    T: Into<IdentityToken> + Clone,
    F: FnOnce(IdPayload) -> Fut,
    Fut: Future<Output = T>,
    G: FnOnce(T, String, String, String, u64) -> Gut,
    Gut: Future<Output = ()>,
{
    if auth_data.code.is_none() {
        return Ok(HttpResponse::Found()
            .append_header((
                "location",
                format!(
                    "{}?login_error={}",
                    env::var("WEB_URI").expect("web uri not provided"),
                    auth_data.error.as_ref().expect("error")
                ),
            ))
            .finish());
    }

    let code = auth_data.code.expect("code");

    let client = Client::builder().timeout(Duration::from_secs(60)).finish();

    let mut response = client
        .post("https://oauth2.googleapis.com/token")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .insert_header(("Accept", "application/json"))
        .timeout(Duration::from_secs(60))
        .send_form(&TokenForm {
            code: code.to_owned(),
            client_id: env::var("CLIENT_ID").expect("client id not provided"),
            client_secret: env::var("CLIENT_SECRET").expect("client secret not provided"),
            redirect_uri: format!(
                "{}/auth",
                env::var("SELF_URI").expect("self uri not provided")
            ),
            grant_type: "authorization_code".to_owned(),
        })
        .await
        .unwrap();

    let json = response.json::<TokenResponse>().await.unwrap();

    let TokenResponse { id_token, .. } = json;

    let client_id = env::var("CLIENT_ID").expect("client id env var set");

    let token = id_token.expect("id_token missing");

    let client = GoogleClient::new(&client_id);
    let decoded_token = client
        .verify_id_token_async(&token)
        .await
        .expect("valid token");
    let payload = decoded_token.get_payload();

    let user = handle_user(payload.clone()).await;

    let idd: IdentityToken = user.clone().into();

    let refresh_secret_key = env::var("REFRESH_SECRET").expect("refresh secret not provided");
    let refresh_secret_key = refresh_secret_key.as_bytes();

    let secret_key = env::var("JWT_SECRET").expect("jwt secret not provided");
    let secret_key = secret_key.as_bytes();

    let access_jwt =
        generate_access_token(&idd.sub, &idd.email, secret_key).expect("jwt generation");
    let (refresh_jwt, expiration) =
        generate_refresh_token(&idd.sub, &idd.email, refresh_secret_key)
            .expect("refresh generation");

    let user_agent = req
        .headers()
        .get("User-Agent")
        .expect("user agent")
        .to_str()
        .expect("to_str");

    let state = auth_data.state.unwrap_or("".to_owned());
    let (device_id, redirect) = if state.contains("SEPARATOR") {
        let mut it = state.split("SEPARATOR").map(|s| s.to_owned());

        let device_id = it.next().unwrap();
        let redirect = it.next().unwrap();

        (device_id, redirect)
    } else {
        (Uuid::new_v4().to_string(), state)
    };

    handle_refresh_token(
        user,
        device_id.clone(),
        refresh_jwt.clone(),
        user_agent.to_owned(),
        expiration,
    )
    .await;

    let id_token = generate_id_token(idd, secret_key).expect("id token");

    Ok(HttpResponse::Found()
        .cookie(cookie("device_id", device_id, 365))
        .cookie(cookie("refresh_token", refresh_jwt, 7))
        .cookie(cookie("access_token", access_jwt, 7))
        .cookie(
            Cookie::build("id_token", id_token)
                .secure(true)
                .path("/")
                .same_site(actix_web::cookie::SameSite::Lax)
                .max_age(time::Duration::days(365))
                .finish(),
        )
        .append_header((
            "location",
            format!(
                "{}{}",
                env::var("WEB_URI").expect("web uri not provided"),
                redirect,
            ),
        ))
        .finish())
}

pub async fn login(request: HttpRequest, login_data: LoginData) -> Result<HttpResponse> {
    let device_id = request.cookie("device_id");
    let redirect = login_data.redirect.unwrap_or("".to_owned());

    let state = if let Some(device_id) = device_id {
        format!("{}SEPARATOR{}", device_id.value(), redirect)
    } else {
        redirect
    };

    Ok(HttpResponse::Found()
        .append_header((
            "location",
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?\
            scope=openid profile email&\
            access_type=offline&\
            include_granted_scopes=true&\
            response_type=code&\
            state={}&\
            redirect_uri={}/auth&\
            client_id={}",
                state,
                env::var("SELF_URI").expect("self uri not provided"),
                env::var("CLIENT_ID").expect("client id not provided")
            ),
        ))
        .finish())
}

pub async fn logout() -> HttpResponse {
    HttpResponse::Found()
        .append_header(("set-cookie", remove_cookie("id_token")))
        .append_header(("set-cookie", remove_cookie("access_token")))
        .append_header(("set-cookie", remove_cookie("refresh_token")))
        .append_header((
            "location",
            env::var("WEB_URI").expect("web uri not provided"),
        ))
        .finish()
}

pub async fn refresh<F, Fut>(req: HttpRequest, validate_refresh_token: F) -> HttpResponse
where
    F: FnOnce(String, String, String) -> Fut,
    Fut: Future<Output = bool>,
{
    let refresh_token = req.cookie("refresh_token");
    let device_id = req.cookie("device_id");
    if refresh_token.is_none() || device_id.is_none() {
        return HttpResponse::Unauthorized()
            .append_header(("set-cookie", remove_cookie("access_token")))
            .append_header(("set-cookie", remove_cookie("refresh_token")))
            .finish();
    }

    let refresh_token = refresh_token.expect("refresh_token");
    let refresh_token = refresh_token.value();

    let device_id = device_id.expect("device_id");
    let device_id = device_id.value();

    let refresh_secret_key = env::var("REFRESH_SECRET").expect("refresh secret not provided");
    let refresh_secret_key = refresh_secret_key.as_bytes();

    let secret_key = env::var("JWT_SECRET").expect("jwt secret not provided");
    let secret_key = secret_key.as_bytes();

    // Validate refresh token
    let decoded = verify_jwt::<Claims>(refresh_token, refresh_secret_key);

    match decoded {
        Ok(decoded_token) => {
            let user_id = decoded_token.sub;
            let email = decoded_token.email;

            let result = validate_refresh_token(
                user_id.clone(),
                device_id.to_owned(),
                refresh_token.to_owned(),
            )
            .await;

            if !result {
                return HttpResponse::Unauthorized()
                    .append_header(("set-cookie", remove_cookie("access_token")))
                    .append_header(("set-cookie", remove_cookie("refresh_token")))
                    .finish();
            }

            // Generate new access token
            let access_jwt = generate_access_token(&user_id, &email, secret_key).unwrap();

            HttpResponse::Ok()
                .cookie(cookie("access_token", access_jwt, 7))
                .json(())
        }
        Err(_) => HttpResponse::Unauthorized()
            .append_header(("set-cookie", remove_cookie("access_token")))
            .append_header(("set-cookie", remove_cookie("refresh_token")))
            .finish(),
    }
}
