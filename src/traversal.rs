use std::collections::HashSet;
use regex::Regex;

use crate::il2cpp::{Il2Cpp, REType};

pub fn visit_in_order<'a, F>(il2cpp: &'a Il2Cpp, visited: &'a mut HashSet<&'a str>, filter: &Option<Regex>, mut emit: F) -> HashSet<&'a str>
where
    F: FnMut(&'a REType),
{
    for name in il2cpp.keys() {
        if let Some(re) = filter {
            if !re.is_match(name) {
                continue
            }
        }
        visit(name, il2cpp, visited, &mut emit);
    }
    visited.clone()
}

fn visit<'a, F>(
    name: &'a str,
    il2cpp: &'a Il2Cpp,
    visited: &mut HashSet<&'a str>,
    emit: &mut F,
) where
    F: FnMut(&'a REType),
{
    if !visited.insert(&name) {
        return;
    }

    let Some(ty) = il2cpp.get(name) else { return };

    if !ty.parent.is_empty() {
        visit(&ty.parent, il2cpp, visited, emit);
    }

    for field in ty.fields.values() {
        visit(&field.r#type, il2cpp, visited, emit);
    }

    for method in ty.methods.values() {
        if let Some(ret) = &method.returns {
            visit(&ret.r#type, il2cpp, visited, emit);
        }
        if let Some(params) = &method.params {
            for param in params {
                visit(&param.r#type, il2cpp, visited, emit);
            }
        }
    }

    emit(ty);
}

