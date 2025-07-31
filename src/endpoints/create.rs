use crate::pasta::PastaFile;
use crate::util::animalnumbers::{to_animal_names, to_u64};
use crate::util::db::{insert, update};
use crate::util::hashids::{to_hashids, to_u64 as hashid_to_u64};
use crate::util::misc::{encrypt, encrypt_file, is_valid_url, remove_expired};
use crate::util::randomstring::{generate_random_string, string_to_id};
use crate::{AppState, Pasta, ARGS};
use crate::endpoints::pasta::PastaTemplate;
use actix_multipart::Multipart;
use actix_web::error::ErrorBadRequest;
use actix_web::{get, web, Error, HttpResponse, Responder};
use askama::Template;
use bytesize::ByteSize;
use futures::TryStreamExt;
use log::warn;
use rand::Rng;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    args: &'a ARGS,
    status: String,
    custom_path: Option<String>,
}







#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(
        IndexTemplate {
            args: &ARGS,
            status: String::from(""),
            custom_path: None,
        }
        .render()
        .unwrap(),
    )
}

#[get("/{status}")]
pub async fn index_with_status(
    param: web::Path<String>,
    data: web::Data<AppState>,
) -> HttpResponse {
    let status = param.into_inner();

    // 检查是否是有效的自定义路径（排除系统路径和状态消息）
    if is_valid_custom_path(&status) {
        // 首先检查是否已存在该路径的pasta（自定义路径或随机字符串路径）
        if let Some(response) = check_existing_path(&data, &status, String::new()).await {
            return response;
        }

        // 显示自定义路径创建界面（使用相同的模板，但添加自定义路径参数）
        return HttpResponse::Ok().content_type("text/html").body(
            IndexTemplate {
                args: &ARGS,
                status: String::from(""),
                custom_path: Some(status),
            }
            .render()
            .unwrap(),
        );
    }

    // 显示普通的状态页面
    return HttpResponse::Ok().content_type("text/html").body(
        IndexTemplate {
            args: &ARGS,
            status,
            custom_path: None,
        }
        .render()
        .unwrap(),
    );
}







/// 根据配置的随机路径长度生成合适的随机ID
fn generate_random_id() -> u64 {
    if ARGS.hash_ids {
        // Hash IDs模式：保持原有逻辑，长度由harsh库决定
        rand::thread_rng().gen_range(1..=u32::MAX as u64)
    } else {
        // Animal names模式：长度由动物名称数量决定
        let animal_count = 64u64;
        let animals_needed = ARGS.random_path_length.max(1).min(6) as u32;

        let min_value = if animals_needed == 1 {
            1u64
        } else {
            animal_count.pow(animals_needed - 1)
        };
        let max_value = animal_count.pow(animals_needed) - 1;

        rand::thread_rng().gen_range(min_value..=max_value)
    }
}

pub fn expiration_to_timestamp(expiration: &str, timenow: i64) -> i64 {
    match expiration {
        "1min" => timenow + 60,
        "10min" => timenow + 60 * 10,
        "1hour" => timenow + 60 * 60,
        "24hour" => timenow + 60 * 60 * 24,
        "3days" => timenow + 60 * 60 * 24 * 3,
        "1week" => timenow + 60 * 60 * 24 * 7,
        "never" => {
            if ARGS.eternal_pasta {
                0
            } else {
                timenow + 60 * 60 * 24 * 7
            }
        }
        _ => {
            log::error!("{}", "Unexpected expiration time!");
            timenow + 60 * 60 * 24 * 7
        }
    }
}

/// receives a file through http Post on url /upload/a-b-c with a, b and c
/// different animals. The client sends the post in response to a form.
// TODO: form field order might need to be changed. In my testing the attachment 
// data is nestled between password encryption key etc <21-10-24, dvdsk> 
pub async fn create(
    data: web::Data<AppState>,
    mut payload: Multipart,
) -> Result<HttpResponse, Error> {
    let mut pastas = data.pastas.lock().unwrap();

    let timenow: i64 = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => {
            log::error!("SystemTime before UNIX EPOCH!");
            0
        }
    } as i64;

    let (id, random_string_path) = if ARGS.random_strings {
        // 使用随机字符串模式
        let random_string = generate_random_string(ARGS.random_path_length as usize);
        let id = string_to_id(&random_string);
        (id, Some(random_string))
    } else {
        // 使用传统模式（animal names或hash IDs）
        (generate_random_id(), None)
    };

    let mut new_pasta = Pasta {
        id,
        content: String::from(""),
        file: None,
        extension: String::from(""),
        private: false,
        readonly: false,
        editable: ARGS.editable,
        encrypt_server: false,
        encrypted_key: Some(String::from("")),
        encrypt_client: false,
        created: timenow,
        read_count: 0,
        burn_after_reads: 0,
        last_read: timenow,
        pasta_type: String::from(""),
        expiration: expiration_to_timestamp(&ARGS.default_expiry, timenow),
        custom_path: None, // 初始化为None，稍后根据需要设置
        random_string_path, // 设置随机字符串路径
    };

    let mut random_key: String = String::from("");
    let mut plain_key: String = String::from("");
    let mut uploader_password = String::from("");

    while let Some(mut field) = payload.try_next().await? {
        let Some(field_name) = field.name() else {
            continue;
        };
        match field_name {
            "uploader_password" => {
                while let Some(chunk) = field.try_next().await? {
                    uploader_password
                        .push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
                }
                continue;
            }
            "random_key" => {
                while let Some(chunk) = field.try_next().await? {
                    random_key = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "privacy" => {
                while let Some(chunk) = field.try_next().await? {
                    let privacy = std::str::from_utf8(&chunk).unwrap();
                    new_pasta.private = match privacy {
                        "public" => false,
                        _ => true,
                    };
                    new_pasta.readonly = match privacy {
                        "readonly" => true,
                        _ => false,
                    };
                    new_pasta.encrypt_client = match privacy {
                        "secret" => true,
                        _ => false,
                    };
                    new_pasta.encrypt_server = match privacy {
                        "private" => true,
                        "secret" => true,
                        _ => false,
                    };
                }
            }
            "plain_key" => {
                while let Some(chunk) = field.try_next().await? {
                    plain_key = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "custom_path" => {
                while let Some(chunk) = field.try_next().await? {
                    let custom_path = std::str::from_utf8(&chunk).unwrap().trim();
                    if !custom_path.is_empty() {
                        new_pasta.custom_path = Some(custom_path.to_string());
                    }
                }
                continue;
            }
            "encrypted_random_key" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.encrypted_key =
                        Some(std::str::from_utf8(&chunk).unwrap().to_string());
                }
                continue;
            }
            "expiration" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.expiration =
                        expiration_to_timestamp(std::str::from_utf8(&chunk).unwrap(), timenow);
                }

                continue;
            }
            "burn_after" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.burn_after_reads = match std::str::from_utf8(&chunk).unwrap() {
                        // give an extra read because the user will be
                        // redirected to the pasta page automatically
                        "1" => 2,
                        "10" => 10,
                        "100" => 100,
                        "1000" => 1000,
                        "10000" => 10000,
                        "0" => 0,
                        _ => {
                            log::error!("{}", "Unexpected burn after value!");
                            0
                        }
                    };
                }

                continue;
            }
            "content" => {
                let mut content = String::from("");
                while let Some(chunk) = field.try_next().await? {
                    content.push_str(std::str::from_utf8(&chunk).unwrap().to_string().as_str());
                }
                if !content.is_empty() {
                    new_pasta.content = content;

                    new_pasta.pasta_type = if is_valid_url(new_pasta.content.as_str()) {
                        String::from("url")
                    } else {
                        String::from("text")
                    };
                }
                continue;
            }
            "syntax_highlight" => {
                while let Some(chunk) = field.try_next().await? {
                    new_pasta.extension = std::str::from_utf8(&chunk).unwrap().to_string();
                }
                continue;
            }
            "file" => {
                if ARGS.no_file_upload {
                    continue;
                }

                let path = field.content_disposition().and_then(|cd| cd.get_filename());

                let path = match path {
                    Some("") => continue,
                    Some(p) => p,
                    None => continue,
                };

                let mut file = match PastaFile::from_unsanitized(path) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Unsafe file name: {e:?}");
                        continue;
                    }
                };

                std::fs::create_dir_all(format!(
                    "{}/attachments/{}",
                    ARGS.data_dir,
                    &new_pasta.id_as_animals()
                ))
                .unwrap();

                let filepath = format!(
                    "{}/attachments/{}/{}",
                    ARGS.data_dir,
                    &new_pasta.id_as_animals(),
                    &file.name()
                );

                let mut f = web::block(|| std::fs::File::create(filepath)).await??;
                let mut size = 0;
                while let Some(chunk) = field.try_next().await? {
                    size += chunk.len();
                    if (new_pasta.encrypt_server
                        && size > ARGS.max_file_size_encrypted_mb * 1024 * 1024)
                        || size > ARGS.max_file_size_unencrypted_mb * 1024 * 1024
                    {
                        return Err(ErrorBadRequest("File exceeded size limit."));
                    }
                    f = web::block(move || f.write_all(&chunk).map(|_| f)).await??;
                }

                file.size = ByteSize::b(size as u64);

                new_pasta.file = Some(file);
                new_pasta.pasta_type = String::from("text");
            }
            field => {
                log::error!("Unexpected multipart field:  {}", field);
            }
        }
    }

    if ARGS.readonly && ARGS.uploader_password.is_some() {
        if uploader_password != ARGS.uploader_password.as_ref().unwrap().to_owned() {
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/incorrect"))
                .finish());
        }
    }

    let id = new_pasta.id;

    if plain_key != *"" && new_pasta.readonly {
        new_pasta.encrypted_key = Some(encrypt(id.to_string().as_str(), &plain_key));
    }

    if new_pasta.encrypt_server && !new_pasta.readonly && new_pasta.content != *"" {
        if new_pasta.encrypt_client {
            new_pasta.content = encrypt(&new_pasta.content, &random_key);
        } else {
            new_pasta.content = encrypt(&new_pasta.content, &plain_key);
        }
    }

    if new_pasta.file.is_some() && new_pasta.encrypt_server && !new_pasta.readonly {
        let filepath = format!(
            "{}/attachments/{}/{}",
            ARGS.data_dir,
            &new_pasta.id_as_animals(),
            &new_pasta.file.as_ref().unwrap().name()
        );
        if new_pasta.encrypt_client {
            encrypt_file(&random_key, &filepath).expect("Failed to encrypt file with random key")
        } else {
            encrypt_file(&plain_key, &filepath).expect("Failed to encrypt file with plain key")
        }
    }

    let encrypt_server = new_pasta.encrypt_server;

    // 获取pasta的访问路径，优先级：自定义路径 > 随机字符串路径 > 传统路径
    let access_path = if let Some(custom_path) = &new_pasta.custom_path {
        custom_path.clone()
    } else if let Some(random_string_path) = &new_pasta.random_string_path {
        random_string_path.clone()
    } else {
        if ARGS.hash_ids {
            to_hashids(id)
        } else {
            to_animal_names(id)
        }
    };

    let has_custom_path = new_pasta.custom_path.is_some();
    let has_random_string_path = new_pasta.random_string_path.is_some();

    pastas.push(new_pasta);

    for (_, pasta) in pastas.iter().enumerate() {
        if pasta.id == id {
            insert(Some(&pastas), Some(pasta));
        }
    }

    if encrypt_server {
        // 对于加密的pasta，仍然使用传统的auth路径
        let slug = if ARGS.hash_ids {
            to_hashids(id)
        } else {
            to_animal_names(id)
        };
        Ok(HttpResponse::Found()
            .append_header(("Location", format!("/auth/{}/success", slug)))
            .finish())
    } else {
        // 对于非加密的pasta，使用自定义路径、随机字符串路径或传统路径
        if has_custom_path || has_random_string_path {
            Ok(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!("{}/{}", ARGS.public_path_as_str(), access_path),
                ))
                .finish())
        } else {
            Ok(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!("{}/upload/{}", ARGS.public_path_as_str(), access_path),
                ))
                .finish())
        }
    }
}

/// 检查路径是否是有效的自定义路径
/// 只有当路径不是系统保留路径且不匹配任何现有pasta时，才认为是自定义路径
fn is_valid_custom_path(path: &str) -> bool {
    // 空路径不是自定义路径
    if path.is_empty() {
        return false;
    }

    // 系统保留路径列表
    let reserved_paths = [
        "upload", "admin", "auth", "auth_admin", "auth_upload", "auth_raw",
        "auth_edit_private", "auth_remove_private", "auth_file", "incorrect", "raw", "url",
        "u", "p", "edit", "remove", "list", "guide", "qr", "file", "static",
        "assets", "favicon.ico", "robots.txt", "sitemap.xml"
    ];

    // 检查是否以保留路径开头
    for reserved in &reserved_paths {
        if path.starts_with(reserved) {
            return false;
        }
    }

    // 检查路径是否包含非法字符
    if path.contains("..") || path.contains("//") {
        return false;
    }

    // 基本的路径验证：只允许字母、数字、连字符、下划线和点
    path.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// 检查是否存在指定路径的pasta（所有类型：动物名称、hash ID、自定义路径、随机字符串路径）
/// 如果存在则返回pasta内容
async fn check_existing_path(
    data: &web::Data<AppState>,
    path: &str,
    password: String,
) -> Option<HttpResponse> {
    // get access to the pasta collection
    let mut pastas = data.pastas.lock().unwrap();

    // remove expired pastas (including this one if needed)
    remove_expired(&mut pastas);

    // 尝试多种方式查找pasta
    let mut pasta_index: usize = 0;
    let mut found: bool = false;

    // 1. 首先检查自定义路径和随机字符串路径
    for (i, pasta) in pastas.iter().enumerate() {
        let matches = if let Some(ref pasta_custom_path) = pasta.custom_path {
            pasta_custom_path == path
        } else if let Some(ref pasta_random_string_path) = pasta.random_string_path {
            pasta_random_string_path == path
        } else {
            false
        };

        if matches {
            pasta_index = i;
            found = true;
            break;
        }
    }

    // 2. 如果没找到，尝试动物名称转换
    if !found {
        if let Ok(id) = to_u64(path) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == id {
                    pasta_index = i;
                    found = true;
                    break;
                }
            }
        }
    }

    // 3. 如果还没找到，尝试hash ID转换
    if !found && ARGS.hash_ids {
        if let Ok(id) = hashid_to_u64(path) {
            for (i, pasta) in pastas.iter().enumerate() {
                if pasta.id == id {
                    pasta_index = i;
                    found = true;
                    break;
                }
            }
        }
    }

    if found {
        // 检查是否需要密码验证
        if pastas[pasta_index].encrypt_server {
            return Some(HttpResponse::Found()
                .append_header((
                    "Location",
                    format!("/auth/{}", pastas[pasta_index].id_as_animals()),
                ))
                .finish());
        }

        // 检查密码
        if pastas[pasta_index].readonly && pastas[pasta_index].encrypted_key.is_some() {
            let key = pastas[pasta_index].encrypted_key.as_ref().unwrap();
            let mcrypt = new_magic_crypt!(key, 256);
            let decrypted_id = mcrypt.decrypt_base64_to_string(&password);

            if decrypted_id.is_err() || decrypted_id.unwrap() != pastas[pasta_index].id.to_string() {
                return Some(HttpResponse::Found()
                    .append_header((
                        "Location",
                        format!("/{}/incorrect", path),
                    ))
                    .finish());
            }
        }

        // increment read count
        pastas[pasta_index].read_count += 1;

        // get current unix time in seconds
        let timenow: i64 = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => {
                log::error!("SystemTime before UNIX EPOCH!");
                0
            }
        } as i64;

        // update last read time
        pastas[pasta_index].last_read = timenow;

        // save the updated read count
        update(Some(&pastas), Some(&pastas[pasta_index]));

        // check if pasta should be burned after reads
        if pastas[pasta_index].burn_after_reads != 0
            && pastas[pasta_index].read_count >= pastas[pasta_index].burn_after_reads
        {
            // serve pasta in template before removing it
            let response = HttpResponse::Ok().content_type("text/html").body(
                PastaTemplate {
                    pasta: &pastas[pasta_index],
                    args: &ARGS,
                }
                .render()
                .unwrap(),
            );

            // remove the pasta
            pastas.remove(pasta_index);
            // update the database
            update(Some(&pastas), None);

            return Some(response);
        }

        // serve pasta in template
        return Some(HttpResponse::Ok().content_type("text/html").body(
            PastaTemplate {
                pasta: &pastas[pasta_index],
                args: &ARGS,
            }
            .render()
            .unwrap(),
        ));
    }

    None
}

/// 通过自定义路径查找pasta的ID（用于重定向到原有功能）
async fn find_pasta_id_by_path(data: &web::Data<AppState>, path: &str) -> Option<String> {
    let pastas = data.pastas.lock().unwrap();

    for pasta in pastas.iter() {
        // 检查自定义路径
        if let Some(ref custom_path) = pasta.custom_path {
            if custom_path == path {
                return Some(pasta.id_as_animals());
            }
        }
        // 检查随机字符串路径
        if let Some(ref random_string_path) = pasta.random_string_path {
            if random_string_path == path {
                return Some(pasta.id_as_animals());
            }
        }
    }

    None
}
