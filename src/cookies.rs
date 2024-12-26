use awc::cookie::{time, Cookie};

pub fn remove_cookie(name: &str) -> String {
    // TODO - remove path? - moliva - 2024/12/26
    format!("{}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/", name)
}

pub fn cookie(name: &str, value: String, max_age_days: i64) -> Cookie {
    Cookie::build(name, value)
        .http_only(true)
        .secure(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(time::Duration::days(max_age_days))
        .finish()
}
