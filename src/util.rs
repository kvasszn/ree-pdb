use serde::{Deserialize, Deserializer};

pub fn sanitize_member_prefix(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub fn sanitize_struct_name(name: &str) -> String {
    name.replace("[]", "_arr").replace(",", "_multi_")
}

pub fn rename_ida_array(name: &str) -> String {
    let dim = 1 + name.matches(',').count();
    let contained = array_contained_type(name);
    if dim > 1 {
        format!("{contained}__{dim}d_arr")
    } else {
        format!("{contained}__arr")
    }
}

pub fn array_contained_type(name: &str) -> String {
    name.replace(",", "").replace("[]", "")
}


pub fn parse_address_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let clean_str = s.trim_start_matches("0x");
    u64::from_str_radix(clean_str, 16).map_err(serde::de::Error::custom)
}

pub fn parse_address_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let clean_str = s.trim_start_matches("0x");
    u32::from_str_radix(clean_str, 16).map_err(serde::de::Error::custom)
}
