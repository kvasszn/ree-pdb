use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: u64,
    pub is_unsigned: bool,
}

pub type EnumMap = HashMap<String, Vec<EnumVariant>>;

fn parse_enum_value(raw: Option<&str>, previous_value: Option<u64>) -> Option<(u64, bool)> {
    let Some(raw) = raw else {
        return Some((
            previous_value.map(|v| v.wrapping_add(1)).unwrap_or(0),
            false,
        ));
    };

    let raw = raw.trim();
    let raw = raw.trim_end_matches(['u', 'U']);

    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        let value = u64::from_str_radix(hex, 16).ok()?;
        return Some((value, value > i32::MAX as u64));
    }

    if raw.starts_with('-') {
        let value = raw.parse::<i64>().ok()?;
        return Some((value as u64, false));
    }

    let value = raw.parse::<u64>().ok()?;
    Some((value, value > i32::MAX as u64))
}

pub fn load_enum_map(path: &Path) -> Result<EnumMap> {
    let text = fs::read_to_string(path)?;
    let namespace_regex = Regex::new(r"namespace\s+([A-Za-z0-9_:]+)\s*\{")?;
    let enum_regex =
        Regex::new(r"enum(?:\s+class)?\s+([A-Za-z0-9_]+)(?:\s*:\s*[A-Za-z0-9_:]+)?\s*\{")?;
    let value_regex = Regex::new(r"^\s*([A-Za-z0-9_]+)\s*(?:=\s*([^,]+))?\s*,?\s*$")?;

    let lines: Vec<&str> = text.lines().collect();
    let mut enums = EnumMap::new();
    let mut namespace_stack: Vec<String> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if let Some(namespace_match) = namespace_regex.captures(line) {
            namespace_stack.push(namespace_match[1].replace("::", "."));
            i += 1;
            continue;
        }

        if line.contains('}') && !line.contains("};") && !namespace_stack.is_empty() {
            namespace_stack.pop();
            i += 1;
            continue;
        }

        if let Some(enum_match) = enum_regex.captures(line) {
            let enum_name = enum_match[1].to_string();
            let mut variants = Vec::new();
            let mut previous_value = None;

            i += 1;
            while i < lines.len() {
                let enum_line = lines[i];
                if enum_line.contains("};") || enum_line.trim() == "}" {
                    break;
                }

                if let Some(value_match) = value_regex.captures(enum_line) {
                    if let Some((value, is_unsigned)) =
                        parse_enum_value(value_match.get(2).map(|m| m.as_str()), previous_value)
                    {
                        previous_value = Some(value);
                        variants.push(EnumVariant {
                            name: value_match[1].to_string(),
                            value,
                            is_unsigned,
                        });
                    }
                }

                i += 1;
            }

            let mut type_name = namespace_stack.join(".");
            if !type_name.is_empty() {
                type_name.push('.');
            }
            type_name.push_str(&enum_name);
            enums.insert(type_name, variants);
        }

        i += 1;
    }

    Ok(enums)
}
