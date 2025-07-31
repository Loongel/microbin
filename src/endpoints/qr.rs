use crate::args::{Args, ARGS};
use crate::endpoints::errors::ErrorTemplate;
use crate::pasta::Pasta;
use crate::util::animalnumbers::to_u64;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::{self, remove_expired, get_base_url_from_request};
use crate::AppState;
use actix_web::{get, web, HttpRequest, HttpResponse};
use askama::Template;

#[derive(Template)]
#[template(path = "qr.html", escape = "none")]
struct QRTemplate<'a> {
    qr: &'a String,
    pasta: &'a Pasta,
    args: &'a Args,
}

#[get("/qr/{id}")]
pub async fn getqr(data: web::Data<AppState>, id: web::Path<String>, req: HttpRequest) -> HttpResponse {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    let id_str = id.into_inner();

    // remove expired pastas (including this one if needed)
    remove_expired(&mut pastas);

    // find the index of the pasta in the collection
    let mut index: usize = 0;
    let mut found: bool = false;

    // 1. 首先检查自定义路径和随机字符串路径
    for (i, pasta) in pastas.iter().enumerate() {
        let matches = if let Some(ref pasta_custom_path) = pasta.custom_path {
            pasta_custom_path == &id_str
        } else if let Some(ref pasta_random_string_path) = pasta.random_string_path {
            pasta_random_string_path == &id_str
        } else {
            false
        };

        if matches {
            index = i;
            found = true;
            break;
        }
    }

    // 2. 如果没找到，尝试动物名称转换
    if !found {
        if let Ok(u64_id) = to_u64(&id_str) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == u64_id {
                    index = i;
                    found = true;
                    break;
                }
            }
        }
    }

    // 3. 如果还没找到，尝试hash ID转换
    if !found && ARGS.hash_ids {
        if let Ok(u64_id) = hashid_to_u64(&id_str) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == u64_id {
                    index = i;
                    found = true;
                    break;
                }
            }
        }
    }

    if found {
        // generate the QR code as an SVG - if its a file or text pastas, this will point to the pasta directly, otherwise to the /url endpoint
        let pasta_path = pastas[index].get_path();
        let base_url = get_base_url_from_request(&req);
        let svg: String = match pastas[index].pasta_type.as_str() {
            "url" => misc::string_to_qr_svg(
                format!("{}/url/{}", base_url, pasta_path).as_str(),
            ),
            _ => misc::string_to_qr_svg(
                format!("{}/{}", base_url, pasta_path).as_str(),
            ),
        };

        // serve qr code in template
        return HttpResponse::Ok().content_type("text/html").body(
            QRTemplate {
                qr: &svg,
                pasta: &pastas[index],
                args: &ARGS,
            }
            .render()
            .unwrap(),
        );
    }

    // otherwise
    // send pasta not found error
    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}
