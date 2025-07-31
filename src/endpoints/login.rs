use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, Result,
};
use actix_web::{get, post, web, HttpRequest};
use askama::Template;
use serde::Deserialize;
use actix_web::http::header::{CONTENT_TYPE, LOCATION, SET_COOKIE};

use futures::future::{ok, Ready};
use std::future::{ready, Future};
use std::pin::Pin;
use std::rc::Rc;


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

#[derive(Deserialize)]
struct LoginQuery {
    redirect_to: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    access_password: String,
    redirect_to: Option<String>,
}

#[get("/login")]
pub async fn get_login(query: web::Query<LoginQuery>) -> Result<HttpResponse> {
    // 如果没有设置ACCESS_PASSWORD，重定向到首页
    if ARGS.access_password.is_none() {
        return Ok(HttpResponse::Found()
            .append_header((LOCATION, "/"))
            .finish());
    }

    let redirect_to = query.redirect_to.as_deref().unwrap_or("/").to_string();
    
    let template = LoginTemplate {
        error_message: None,
        redirect_to,
    };

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(template.render().unwrap()))
}

#[post("/login")]
pub async fn post_login(form: web::Form<LoginForm>) -> Result<HttpResponse> {
    // 如果没有设置ACCESS_PASSWORD，重定向到首页
    if ARGS.access_password.is_none() {
        return Ok(HttpResponse::Found()
            .append_header((LOCATION, "/"))
            .finish());
    }

    let redirect_to = form.redirect_to.as_deref().unwrap_or("/").to_string();

    // 验证密码
    if let Some(ref correct_password) = ARGS.access_password {
        if form.access_password == *correct_password {
            // 密码正确，设置cookie并重定向
            let cookie = "microbin_auth=verified; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"; // 24小时有效
            return Ok(HttpResponse::Found()
                .append_header((SET_COOKIE, cookie))
                .append_header((LOCATION, redirect_to))
                .finish());
        }
    }

    // 密码错误，显示错误信息
    let template = LoginTemplate {
        error_message: Some("Incorrect password. Please try again.".to_string()),
        redirect_to,
    };

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(template.render().unwrap()))
}

#[get("/logout")]
pub async fn logout() -> Result<HttpResponse> {
    // 清除cookie并重定向到登录页面
    let cookie = "microbin_auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
    Ok(HttpResponse::Found()
        .append_header((SET_COOKIE, cookie))
        .append_header((LOCATION, "/login"))
        .finish())
}
