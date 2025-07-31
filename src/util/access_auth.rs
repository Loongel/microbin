use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, Result,
};
use actix_web::http::header::{CONTENT_TYPE, LOCATION};
use futures::future::{ok, Ready};
use std::future::{ready, Future};
use std::pin::Pin;
use std::rc::Rc;
use askama::Template;

use crate::args::ARGS;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error_message: Option<String>,
    redirect_to: String,
}

pub struct AccessAuth;

impl<S, B> Transform<S, ServiceRequest> for AccessAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AccessAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AccessAuthMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct AccessAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AccessAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            // 如果没有设置ACCESS_PASSWORD，直接通过
            if ARGS.access_password.is_none() {
                return service.call(req).await;
            }

            let path = req.path();
            
            // 登录相关路径不需要验证
            if path == "/login" || path.starts_with("/static/") || path == "/favicon.ico" {
                return service.call(req).await;
            }

            // 检查session中是否已经验证过
            if let Some(cookie) = req.headers().get("cookie") {
                if let Ok(cookie_str) = cookie.to_str() {
                    if cookie_str.contains("microbin_auth=verified") {
                        return service.call(req).await;
                    }
                }
            }

            // 需要验证，重定向到登录页面
            let redirect_url = format!("/login?redirect_to={}", urlencoding::encode(path));
            let response = HttpResponse::Found()
                .append_header((LOCATION, redirect_url))
                .finish();
            
            Ok(req.into_response(response))
        })
    }
}