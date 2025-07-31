use rand::Rng;

/// 生成指定长度的随机字符串
/// 使用URL安全的字符集：a-z, A-Z, 0-9
pub fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// 将随机字符串转换为u64 ID（用于内部存储）
/// 这是一个简单的哈希函数，将字符串映射到数字
/// 确保结果在合理范围内，避免数据库溢出
pub fn string_to_id(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    // 限制在32位范围内，避免数据库问题
    (hasher.finish() % (u32::MAX as u64)) + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_string() {
        let s1 = generate_random_string(4);
        let s2 = generate_random_string(4);
        
        assert_eq!(s1.len(), 4);
        assert_eq!(s2.len(), 4);
        assert_ne!(s1, s2); // 应该生成不同的字符串
        
        // 检查字符是否都在允许的字符集中
        for c in s1.chars() {
            assert!(c.is_ascii_alphanumeric());
        }
    }

    #[test]
    fn test_string_to_id() {
        let s1 = "abcd";
        let s2 = "efgh";
        
        let id1 = string_to_id(s1);
        let id2 = string_to_id(s2);
        
        assert_ne!(id1, id2); // 不同字符串应该产生不同ID
        
        // 相同字符串应该产生相同ID
        assert_eq!(string_to_id(s1), string_to_id(s1));
    }
}
