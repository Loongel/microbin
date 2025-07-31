use actix_multipart::Multipart;
use actix_web::{get, post, web, Error, HttpResponse};

use crate::args::ARGS;
use crate::endpoints::errors::ErrorTemplate;
use crate::pasta::PastaFile;
use crate::util::animalnumbers::to_u64;
use crate::util::auth;
use crate::util::db::delete;
use crate::util::hashids::to_u64 as hashid_to_u64;
use crate::util::misc::{decrypt, remove_expired};
use crate::AppState;
use askama::Template;
use std::fs;

#[get("/remove/{id}")]
pub async fn remove(data: web::Data<AppState>, id: web::Path<String>) -> HttpResponse {
    let mut pastas = data.pastas.lock().unwrap();

    let id_str = id.into_inner();

    // 查找pasta，支持自定义路径、随机字符串路径、动物名称和hash ID
    let mut found_index: Option<usize> = None;

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
            found_index = Some(i);
            break;
        }
    }

    // 2. 如果没找到，尝试动物名称转换
    if found_index.is_none() {
        if let Ok(id) = to_u64(&id_str) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == id {
                    found_index = Some(i);
                    break;
                }
            }
        }
    }

    // 3. 如果还没找到，尝试hash ID转换
    if found_index.is_none() && ARGS.hash_ids {
        if let Ok(id) = hashid_to_u64(&id_str) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == id {
                    found_index = Some(i);
                    break;
                }
            }
        }
    }

    if let Some(i) = found_index {
        let pasta = &pastas[i];
        let pasta_id = pasta.id;
        let pasta_id_as_animals = pasta.id_as_animals();

        // if it's encrypted or read-only, it needs password to be deleted
        if pasta.encrypt_server || pasta.readonly {
            return HttpResponse::Found()
                .append_header((
                    "Location",
                    format!("/auth_remove_private/{}", pasta_id_as_animals),
                ))
                .finish();
        }

        // remove the file itself
        if let Some(PastaFile { name, .. }) = &pasta.file {
            if fs::remove_file(format!(
                "{}/attachments/{}/{}",
                ARGS.data_dir,
                pasta_id_as_animals,
                name
            ))
            .is_err()
            {
                log::error!("Failed to delete file {}!", name)
            }

            // and remove the containing directory
            if fs::remove_dir(format!(
                "{}/attachments/{}/",
                ARGS.data_dir,
                pasta_id_as_animals
            ))
            .is_err()
            {
                log::error!("Failed to delete directory {}!", name)
            }
        }

        // remove it from in-memory pasta list
        pastas.remove(i);

        delete(Some(&pastas), Some(pasta_id));

        return HttpResponse::Found()
            .append_header(("Location", format!("{}/list", ARGS.public_path_as_str())))
            .finish();
    }

    remove_expired(&mut pastas);

    HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap())
}

#[post("/remove/{id}")]
pub async fn post_remove(
    data: web::Data<AppState>,
    id: web::Path<String>,
    payload: Multipart,
) -> Result<HttpResponse, Error> {
    let id = if ARGS.hash_ids {
        hashid_to_u64(&id).unwrap_or(0)
    } else {
        to_u64(&id.into_inner()).unwrap_or(0)
    };

    let mut pastas = data.pastas.lock().unwrap();

    remove_expired(&mut pastas);

    let password = auth::password_from_multipart(payload).await?;

    for (i, pasta) in pastas.iter().enumerate() {
        if pasta.id == id {
            if pastas[i].readonly || pastas[i].encrypt_server {
                if password != *"" {
                    let res = decrypt(pastas[i].content.to_owned().as_str(), &password);
                    if res.is_ok() {
                        // remove the file itself
                        if let Some(PastaFile { name, .. }) = &pasta.file {
                            if fs::remove_file(format!(
                                "{}/attachments/{}/{}",
                                ARGS.data_dir,
                                pasta.id_as_animals(),
                                name
                            ))
                            .is_err()
                            {
                                log::error!("Failed to delete file {}!", name)
                            }

                            // and remove the containing directory
                            if fs::remove_dir(format!(
                                "{}/attachments/{}/",
                                ARGS.data_dir,
                                pasta.id_as_animals()
                            ))
                            .is_err()
                            {
                                log::error!("Failed to delete directory {}!", name)
                            }
                        }

                        // remove it from in-memory pasta list
                        pastas.remove(i);

                        delete(Some(&pastas), Some(id));

                        return Ok(HttpResponse::Found()
                            .append_header((
                                "Location",
                                format!("{}/list", ARGS.public_path_as_str()),
                            ))
                            .finish());
                    } else {
                        return Ok(HttpResponse::Found()
                            .append_header((
                                "Location",
                                format!("/auth_remove_private/{}/incorrect", pasta.id_as_animals()),
                            ))
                            .finish());
                    }
                } else {
                    return Ok(HttpResponse::Found()
                        .append_header((
                            "Location",
                            format!("/auth_remove_private/{}/incorrect", pasta.id_as_animals()),
                        ))
                        .finish());
                }
            }

            return Ok(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!(
                        "{}/upload/{}",
                        ARGS.public_path_as_str(),
                        pastas[i].id_as_animals()
                    ),
                ))
                .finish());
        }
    }

    Ok(HttpResponse::Ok()
        .content_type("text/html")
        .body(ErrorTemplate { args: &ARGS }.render().unwrap()))
}
