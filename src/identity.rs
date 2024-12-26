use std::{
    cell::{Ref, RefCell},
    env,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use actix_web::{
    body::EitherBody,
    dev::{Extensions, Payload, Service, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, Result,
};
use awc::cookie::Cookie;
use futures::{
    future::{ok, FutureExt, Ready},
    Future,
};
use google_jwt_verify::{IdPayload, Token};
use http::Method;

use crate::{auth::Claims, jwt::verify_jwt};

#[derive(Clone)]
pub struct Identity(HttpRequest);

impl FromRequest for Identity {
    type Error = Error;
    type Future = Ready<Result<Identity, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ok(Identity(req.clone()))
    }
}

impl Identity {
    /// Return the claimed identity of the user associated request or
    /// ``None`` if no identity can be found associated with the request.
    pub fn identity(&self) -> Option<Claims> {
        Identity::get_identity(&self.0.extensions())
    }

    /// Remember identity.
    pub fn remember(&self, identity: Claims) {
        if let Some(id) = self.0.extensions_mut().get_mut::<IdentityItem>() {
            id.id = Some(identity);
        }
    }

    /// This method is used to 'forget' the current identity on subsequent
    /// requests.
    pub fn forget(&self) {
        if let Some(id) = self.0.extensions_mut().get_mut::<IdentityItem>() {
            id.id = None;
        }
    }

    fn get_identity(extensions: &Ref<'_, Extensions>) -> Option<Claims> {
        if let Some(id) = extensions.get::<IdentityItem>() {
            id.id.clone()
        } else {
            None
        }
    }
}

struct IdentityItem {
    id: Option<Claims>,
}

#[derive(Clone)]
pub struct IdToken {
    pub email: String,
    pub name: String,
}

impl From<Token<IdPayload>> for IdToken {
    fn from(t: Token<IdPayload>) -> Self {
        let email = t.get_payload().get_email();
        let name = t.get_payload().get_name();

        Self { email, name }
    }
}

pub struct IdentityService;

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for IdentityService
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S: 'static,
    S::Future: 'static,
    B: 'static,
{
    // type Response = ServiceResponse<B>;
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = IdentityMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(IdentityMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct IdentityMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S> Clone for IdentityMiddleware<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

impl<S, B> Service<ServiceRequest> for IdentityMiddleware<S>
where
    B: 'static,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.method() == Method::OPTIONS {
            let srv = self.service.clone();
            return async move {
                let fut = srv.call(req);
                let res = fut.await?;

                Ok(res.map_into_left_body())
            }
            .boxed_local();
        }
        if ["/login", "/auth", "/refresh", "/logout"].contains(&req.path()) {
            let srv = self.service.clone();

            return async move {
                let fut = srv.call(req);
                let res = fut.await?;

                Ok(res.map_into_left_body())
            }
            .boxed_local();
        }

        let cookies = req.cookies().expect("cookies").clone();
        let srv = self.service.clone();

        let id = validate_auth_(&cookies);
        if id.is_none() {
            // let sr = ErrorUnauthorized("Unauthorized: Missing or invalid token");
            let sr = async move {
                Ok(ServiceResponse::new(
                    req.request().clone(),
                    HttpResponse::Unauthorized().finish(),
                )
                .map_into_right_body())
            }
            .boxed_local();

            return sr;
        }

        async move {
            req.extensions_mut().insert(IdentityItem { id });

            let fut = srv.borrow_mut().call(req);
            let res = fut.await?;
            res.request().extensions_mut().remove::<IdentityItem>();

            Ok(res.map_into_left_body())
        }
        .boxed_local()
    }
}

fn validate_auth_(headers: &[Cookie<'static>]) -> Option<Claims> {
    let authorization = headers.iter().find(|c| c.name() == "access_token");

    if let Some(identity_token) = authorization {
        let secret_key = env::var("JWT_SECRET").unwrap();
        let secret_key = secret_key.as_bytes();

        let value = identity_token.value();

        let yas = verify_jwt(value, secret_key);

        if let Ok(yas) = yas {
            Some(yas)
        } else {
            None
        }
    } else {
        None
    }
}

