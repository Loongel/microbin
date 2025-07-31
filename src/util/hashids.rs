use harsh::Harsh;
use lazy_static::lazy_static;
use crate::args::ARGS;

lazy_static! {
    pub static ref HARSH: Harsh = {
        let length = ARGS.random_path_length.max(1).min(10) as usize; // 限制在1-10之间
        Harsh::builder().length(length).build().unwrap()
    };
}

pub fn to_hashids(number: u64) -> String {
    HARSH.encode(&[number])
}

pub fn to_u64(hash_id: &str) -> Result<u64, &str> {
    let ids = HARSH
        .decode(hash_id)
        .map_err(|_e| "Failed to decode hash ID")?;
    let id = ids.first().ok_or("No ID found in hash ID")?;
    Ok(*id)
}
