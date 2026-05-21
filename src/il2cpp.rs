use std::{
    collections::{HashMap, HashSet}
};

use crate::util::*;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer};
use pdb_wrapper::{
    PDBFunction, PDBType, StructField,
    pdb_meta::{CallingConvention, SimpleTypeKind},
};
use strum::EnumString;


fn deserialize_fields<'de, D>(deserializer: D) -> Result<HashMap<String, REField>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut map: HashMap<String, REField> = HashMap::deserialize(deserializer)?;
    for (key, t_data) in map.iter_mut() {
        t_data.name = key.clone();
    }
    Ok(map)
}

fn deserialize_methods<'de, D>(deserializer: D) -> Result<HashMap<String, REMethod>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut map: HashMap<String, REMethod> = HashMap::deserialize(deserializer)?;
    for (key, t_data) in map.iter_mut() {
        t_data.name = key.clone();
    }
    Ok(map)
}

pub fn deserialize_il2cpp<'de, D>(deserializer: D) -> Result<Il2Cpp, D::Error>
where
    D: Deserializer<'de>,
{
    let mut map: HashMap<String, REType> = HashMap::deserialize(deserializer)?;
    for (key, t_data) in map.iter_mut() {
        t_data.name = key.clone();
    }
    Ok(map)
}

pub type Il2Cpp = HashMap<String, REType>;

// i really should impl Deserialize myself to get better descriptions of the type,
// or just convert to PDBType, etc before adding everything
#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct REType {
    #[serde(skip)]
    pub name: String,
    #[serde(default, deserialize_with = "parse_address_u64")]
    pub address: u64,
    #[serde(deserialize_with = "parse_address_u32")]
    crc: u32,
    #[serde(default, deserialize_with = "deserialize_type_flags")]
    pub flags: Vec<RETypeFlag>,
    #[serde(default, deserialize_with = "deserialize_fields")]
    pub fields: HashMap<String, REField>,
    #[serde(deserialize_with = "parse_address_u64")]
    fqn: u64,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    pub is_generic_type: bool,
    #[serde(default)]
    is_generic_type_definition: bool,
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: HashMap<String, REMethod>,
    #[serde(default)]
    name_hierarchy: Vec<String>,
    #[serde(default)]
    pub native_typename: String,
    #[serde(default)]
    pub parent: String,
    #[serde(default)]
    pub properties: HashMap<String, REProperty>,
    #[serde(default, deserialize_with = "parse_address_u32")]
    pub size: u32,
}

impl REType {
    #[inline]
    pub fn is_enum_or_value_type(&self) -> bool {
        self.is_enum() || self.is_value_type()
    }

    #[inline]
    pub fn is_enum(&self) -> bool {
        self.parent.as_str() == "System.Enum"
    }

    #[inline]
    pub fn is_value_type(&self) -> bool {
        self.parent.as_str() == "System.ValueType"
    }

    fn get_field_offset(&self, field: &REField) -> u64 {
        if self.is_enum_or_value_type() {
            field.offset_from_fieldptr as u64
        } else {
            field.offset_from_base as u64
        }
    }

    fn get_own_struct_fields(
        &self,
        il2cpp: &Il2Cpp,
        inherited_name_prefix: Option<&str>,
        include_static: bool,
    ) -> Vec<StructField> {
        let mut struct_fields = vec![];
        for (f_name, field) in &self.fields {
            if !include_static && field.flags.contains(&REFieldFlag::Static) {
                continue;
            }

            let ty = get_pdb_type(&field.r#type, il2cpp);
            let name = inherited_name_prefix
                .map(|prefix| format!("{prefix}__{f_name}"))
                .unwrap_or_else(|| f_name.clone());
            let sf = StructField {
                ty,
                name,
                offset: self.get_field_offset(field),
                is_static: field.flags.contains(&REFieldFlag::Static),
            };
            struct_fields.push(sf);
        }
        struct_fields
    }

    pub fn get_struct_fields(&self, il2cpp: &Il2Cpp) -> Result<(Vec<StructField>, usize)> {
        let mut struct_fields = vec![];
        let mut inherited_fields_added = 0;

        if !self.is_enum_or_value_type() {
            let mut ancestors = vec![];
            let mut parent_name = self.parent.as_str();
            let mut seen = HashSet::new();

            while !parent_name.is_empty()
                && parent_name != "System.ValueType"
                && parent_name != "System.Enum"
                && seen.insert(parent_name.to_string())
            {
                let Some(parent) = il2cpp.get(parent_name) else {
                    break;
                };
                ancestors.push(parent);
                parent_name = parent.parent.as_str();
            }

            ancestors.reverse();
            for ancestor in ancestors {
                let prefix = format!("__base_{}", sanitize_member_prefix(&ancestor.name));
                let mut fields = ancestor.get_own_struct_fields(il2cpp, Some(&prefix), false);
                inherited_fields_added += fields.len();
                struct_fields.append(&mut fields);
            }
        }

        struct_fields.append(&mut self.get_own_struct_fields(il2cpp, None, true));
        struct_fields.sort_by_key(|f| f.offset);
        Ok((struct_fields, inherited_fields_added))
    }

    pub fn iter_vtable_methods<'a>(&'a self, il2cpp: &'a Il2Cpp) -> impl Iterator<Item = (u64, &'a REMethod)>
    {
        let mut ancestors = vec![self];
        let mut parent_name = self.parent.as_str();
        let mut seen_classes = HashSet::new();

        while !parent_name.is_empty() && seen_classes.insert(parent_name.to_string()) {
            if let Some(parent) = il2cpp.get(parent_name) {
                ancestors.push(parent);
                parent_name = parent.parent.as_str();
            } else {
                break;
            }
        }
        let mut filled_slots = HashSet::new();
        ancestors.into_iter()
            .flat_map(|class| class.methods.values())
            .filter_map(move |method| {
                if method.flags.contains(&REMethodFlag::Static) {
                    return None
                }
                if !method.flags.contains(&REMethodFlag::Virtual)
                    && !method.flags.contains(&REMethodFlag::Abstract)
                    && !method.flags.contains(&REMethodFlag::NewSlot) {
                    return None
                }
                if let Some(idx) = method.vtable_index {
                    filled_slots.insert(idx)
                        .then_some((idx as u64, method))
                } else {
                    None
                }
            })
    }

    pub fn get_struct_vtable(&self, il2cpp: &Il2Cpp) -> Result<(u64, Vec<StructField>)> {
        if !self.flags.contains(&RETypeFlag::ManagedVTable) {
            bail!("Type {} does not have a Managed VTable", self.name)
        }

        let mut vtable_size = 8;
        let mut vtable_fields = vec![];
        vtable_fields.push(StructField {
            ty: PDBType::Pointer(Box::new(PDBType::SimpleType(SimpleTypeKind::Void))),
            name: "__type_definition".to_string(),
            offset: 0,
            is_static: false
        });

        for (vtable_index, method) in self.iter_vtable_methods(il2cpp) {
            let pdb_func = method.get_pdb_function(Some(&self.name), il2cpp);
            let func_ptr_type = PDBType::Pointer(Box::new(PDBType::Function(pdb_func)));
            let offset = vtable_index as u64 * 8 + 8;
            vtable_fields.push(StructField {
                ty: func_ptr_type,
                name: method.name.clone(),
                offset,
                is_static: false,
            });
            vtable_size = vtable_size.max(offset + 8); // could just use max vtable_index value
        }
        vtable_fields.sort_by_key(|f| f.offset);
        Ok((vtable_size, vtable_fields))
    }

    pub fn to_pdb_type(&self) -> Result<PDBType> {
        let is_enum = self.parent == "System.Enum";
        let is_value_type = self.parent == "System.ValueType";
        //let is_array = self.parent == "System.Array";
        let t = match self.name.as_str() {
            "System.Boolean" => PDBType::SimpleType(SimpleTypeKind::Boolean8),
            "System.SByte" => PDBType::SimpleType(SimpleTypeKind::SByte),
            "System.Int16" => PDBType::SimpleType(SimpleTypeKind::Int16),
            "System.Int32" => PDBType::SimpleType(SimpleTypeKind::Int32),
            "System.Int64" => PDBType::SimpleType(SimpleTypeKind::Int64),
            "System.Byte" => PDBType::SimpleType(SimpleTypeKind::Byte),
            "System.UInt16" => PDBType::SimpleType(SimpleTypeKind::UInt16),
            "System.UInt32" => PDBType::SimpleType(SimpleTypeKind::UInt32),
            "System.UInt64" => PDBType::SimpleType(SimpleTypeKind::UInt64),
            "System.Single" => PDBType::SimpleType(SimpleTypeKind::Float32),
            "System.Double" => PDBType::SimpleType(SimpleTypeKind::Float64),
            "System.Char" => PDBType::SimpleType(SimpleTypeKind::WideCharacter),
            "System.Void" => PDBType::SimpleType(SimpleTypeKind::Void),
            "System.Guid" => {
                PDBType::ConstantArray(Box::new(PDBType::SimpleType(SimpleTypeKind::Byte)), 16)
            }
            _ => {
                if is_enum || is_value_type {
                    PDBType::Struct(self.name.to_string())
                } else {
                    PDBType::Pointer(Box::new(PDBType::Struct(self.name.to_string())))
                }
            } //_ => bail!("Unmatched type"),
        };
        Ok(t)
    }
}

#[derive(Debug, PartialEq, EnumString)]
pub enum RETypeFlag {
    ContainsGenericParameters,
    Finalize,
    NativeCtor,
    NativeType,
    ClassSemanticsMask,
    Public,
    NestedPublic,
    NestedFamily,
    SequentialLayout,
    ExplicitLayout,
    Sealed,
    Private,
    Abstract,
    Serializable,
    BeforeFieldInit,
    LocalHeap,
    ManagedVTable
}

fn deserialize_type_flags<'de, D>(deserializer: D) -> Result<Vec<RETypeFlag>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let flags: Vec<RETypeFlag> = value.split('|')
        .filter_map(|s| {
            let s = s.trim();
            match s.parse::<RETypeFlag>() {
                Ok(flag) => Some(flag),
                Err(_) => {
                    eprintln!("[WARN] Unknown RETypeFlag: {s:?}");
                    None
                }
            }
        })
    .collect();
    //let flags = flags.map_err(serde::de::Error::custom)?;
    Ok(flags)
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct REField {
    #[serde(skip)]
    pub name: String,
    id: u64,
    pub init_data_index: u32,
    #[serde(deserialize_with = "parse_address_u32")]
    pub offset_from_base: u32,
    #[serde(deserialize_with = "parse_address_u32")]
    pub offset_from_fieldptr: u32,
    pub r#type: String,
    #[serde(default, deserialize_with = "deserialize_field_flags")]
    pub flags: Vec<REFieldFlag>,
}


#[derive(Debug, PartialEq, EnumString)]
pub enum REFieldFlag {
    PointerOrRef,
    Pointer,
    Private,
    NotSerialized,
    FamANDAssem,
    Family,
    Static,
    InitOnly,
    HasFieldRVA,
    ExposeMember,
    Literal,
    SpecialName,
    RTSpecialName,
    HasDefault,
}

fn deserialize_field_flags<'de, D>(deserializer: D) -> Result<Vec<REFieldFlag>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let flags: Vec<REFieldFlag> = value.split('|')
        .filter_map(|s| {
            let s = s.trim();
            match s.parse::<REFieldFlag>() {
                Ok(flag) => Some(flag),
                Err(_) => {
                    eprintln!("[WARN] Unknown REFieldFlag: {s:?}");
                    None
                }
            }
        })
    .collect();
    //let flags = flags.map_err(serde::de::Error::custom)?;
    Ok(flags)
}


#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct REMethod {
    #[serde(skip)]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_method_flags")]
    pub flags: Vec<REMethodFlag>,
    #[serde(deserialize_with = "parse_address_u64")]
    pub function: u64,
    id: u64,
    #[serde(default, deserialize_with = "deserialize_impl_flags")]
    pub impl_flags: Vec<REImplFlag>,
    pub invoke_id: u32,
    pub params: Option<Vec<REParam>>,
    pub returns: Option<REParam>,
    pub vtable_index: Option<u32>,
}

impl REMethod {
    pub fn symbol_name(&self, r#type: &REType) -> String {
        format!("{}::{}", r#type.name, self.name)
    }
    pub fn signature(&self, r#type: &REType) -> String {
        let params = self
            .params
            .as_ref()
            .map(|p| {
                let mut params = String::new();
                for (i, param) in p.iter().enumerate() {
                    params.push_str(&param.r#type);
                    if !param.name.is_empty() {
                        params.push(' ');

                        params.push_str(&param.name);
                    }
                    if i + 1 != p.len() {
                        params.push(',');
                    }
                }
                params
            })
            .unwrap_or("".to_string());
        let signature = format!("{}({})", self.symbol_name(r#type), params);
        signature
    }

    pub fn get_pdb_function(&self, class: Option<&str>, il2cpp: &Il2Cpp) -> PDBFunction {
        let ret_type = self
            .returns
            .as_ref()
            .and_then(|f| il2cpp.get(&f.r#type))
            .and_then(|t| t.to_pdb_type().ok())
            // this never really happens
            .unwrap_or_else(|| PDBType::SimpleType(SimpleTypeKind::Void));

        // vmctx passed in here
        let mut param_types = vec![PDBType::Pointer(Box::new(PDBType::SimpleType(
            SimpleTypeKind::Void,
        )))];

        if self.impl_flags.contains(&REImplFlag::HasThis) {
            if let Some(class_name) = class {
                param_types.push(PDBType::Pointer(Box::new(PDBType::Struct(
                    class_name.to_string(),
                ))));
            }
        }

        if let Some(params) = &self.params {
            for param in params {
                param_types.push(get_pdb_type(&param.r#type, il2cpp));
                /*let pdb_type = il2cpp
                    .get(&param.r#type)
                    .and_then(|t| t.to_pdb_type().ok())
                    .unwrap_or_else(|| PDBType::SimpleType(SimpleTypeKind::Void));
                param_types.push(pdb_type);*/
            }
        }

        let cconv = CallingConvention::NearFast;

        //let class_type = class.map(|x| PDBType::Struct(x.to_string()));
        //PDBFunction::new(ret_type, &param_types, class_type, cconv)
        PDBFunction::new_ex(ret_type, param_types, None, cconv)
    }
}

#[derive(Debug, PartialEq, EnumString)]
pub enum REMethodFlag {
    Private,
    FamANDAssem,
    Final,
    Family,
    Static,
    Virtual,
    HideBySig,
    SpecialName,
    RTSpecialName,
    NewSlot,
    Abstract,
    NoInlining,
}

fn deserialize_method_flags<'de, D>(deserializer: D) -> Result<Vec<REMethodFlag>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let flags = value.split('|')
        .filter_map(|s| {
            let s = s.trim();
            match s.parse::<REMethodFlag>() {
                Ok(flag) => Some(flag),
                Err(_) => {
                    eprintln!("[WARN] Unknown REMethodFlag: {s:?}");
                    None
                }
            }
        })
        .collect();
    Ok(flags)
}

#[derive(Debug, PartialEq, EnumString)]
pub enum REImplFlag {
    AggressiveOptimization,
    EmptyCtor,
    ExposeMember,
    NoInlining,
    Native,
    HasRetVal,
    InternalCall,
    HasThis,
    ContainsGenericParameters,
    AggressiveInlining,
}

fn deserialize_impl_flags<'de, D>(deserializer: D) -> Result<Vec<REImplFlag>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let flags: Vec<REImplFlag> = value.split('|')
        .filter_map(|s| {
            let s = s.trim();
            match s.parse::<REImplFlag>() {
                Ok(flag) => Some(flag),
                Err(_) => {
                    eprintln!("[WARN] Unknown REImplFlag: {s:?}");
                    None
                }
            }
        })
    .collect();
    //let flags = flags.map_err(serde::de::Error::custom)?;
    Ok(flags)
}


#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct REParam {
    pub name: String,
    pub r#type: String,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct REProperty {
    #[serde(skip)]
    pub name: String,
    pub getter: String,
    pub id: u32,
    pub setter: String,
}


// idk if this should be part of the REType, or something else
// lowkirkenuenly i should rewrite this whole program
pub fn get_pdb_type(type_name: &str, il2cpp: &Il2Cpp) -> PDBType {
    match type_name {
        "System.Boolean" => PDBType::SimpleType(SimpleTypeKind::Boolean8),
        "System.SByte" => PDBType::SimpleType(SimpleTypeKind::SByte),
        "System.Int16" => PDBType::SimpleType(SimpleTypeKind::Int16),
        "System.Int32" => PDBType::SimpleType(SimpleTypeKind::Int32),
        "System.Int64" => PDBType::SimpleType(SimpleTypeKind::Int64),
        "System.Byte" => PDBType::SimpleType(SimpleTypeKind::Byte),
        "System.UInt16" => PDBType::SimpleType(SimpleTypeKind::UInt16),
        "System.UInt32" => PDBType::SimpleType(SimpleTypeKind::UInt32),
        "System.UInt64" => PDBType::SimpleType(SimpleTypeKind::UInt64),
        "System.Single" => PDBType::SimpleType(SimpleTypeKind::Float32),
        "System.Double" => PDBType::SimpleType(SimpleTypeKind::Float64),
        "System.Char" => PDBType::SimpleType(SimpleTypeKind::WideCharacter),
        "System.Void" => PDBType::SimpleType(SimpleTypeKind::Void),
        "System.Guid" => {
            PDBType::ConstantArray(Box::new(PDBType::SimpleType(SimpleTypeKind::Byte)), 16)
        }
        _ => {
            if let Some(t) = il2cpp.get(type_name) {
                if t.parent == "System.ValueType" || t.parent == "System.Enum" {
                    return PDBType::Struct(type_name.to_string());
                }
            }
            PDBType::Pointer(Box::new(PDBType::Struct(type_name.to_string())))
        }
    }
}

pub fn to_pdb_type(name: &str, parent: &str) -> Result<PDBType> {
    let is_enum = parent == "System.Enum";
    let is_value_type = parent == "System.ValueType";
    let t = match name {
        "System.Boolean" => PDBType::SimpleType(SimpleTypeKind::Boolean8),
        "System.SByte" => PDBType::SimpleType(SimpleTypeKind::SByte),
        "System.Int16" => PDBType::SimpleType(SimpleTypeKind::Int16),
        "System.Int32" => PDBType::SimpleType(SimpleTypeKind::Int32),
        "System.Int64" => PDBType::SimpleType(SimpleTypeKind::Int64),
        "System.Byte" => PDBType::SimpleType(SimpleTypeKind::Byte),
        "System.UInt16" => PDBType::SimpleType(SimpleTypeKind::UInt16),
        "System.UInt32" => PDBType::SimpleType(SimpleTypeKind::UInt32),
        "System.UInt64" => PDBType::SimpleType(SimpleTypeKind::UInt64),
        "System.Single" => PDBType::SimpleType(SimpleTypeKind::Float32),
        "System.Double" => PDBType::SimpleType(SimpleTypeKind::Float64),
        "System.Char" => PDBType::SimpleType(SimpleTypeKind::WideCharacter),
        "System.Void" => PDBType::SimpleType(SimpleTypeKind::Void),
        "System.Guid" => {
            PDBType::ConstantArray(Box::new(PDBType::SimpleType(SimpleTypeKind::Byte)), 16)
        }
        _ => {
            if is_enum || is_value_type {
                PDBType::Struct(name.to_string())
            } else {
                PDBType::Pointer(Box::new(PDBType::Struct(name.to_string())))
            }
        } //_ => bail!("Unmatched type"),
    };
    Ok(t)
}
