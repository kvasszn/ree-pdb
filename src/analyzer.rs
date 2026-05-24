use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind, Register};
use object::read::pe::{PeFile64, };
use object::{Object, ObjectSection, LittleEndian};
use crate::il2cpp::{Il2Cpp, REFieldFlag, REMethod, REMethodFlag, REType};

use anyhow::{Result};

pub const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;
pub const BASE_ADDRESS: usize = 0x140000000;

pub fn print_instruction<F: Formatter>(output: &mut String, instruction: &mut Instruction, instr_bytes: &[u8], formatter: &mut F) {

    formatter.format(instruction, output);
    print!("{:016X} ", instruction.ip());
    for b in instr_bytes.iter() {
        print!("{:02X}", b);
    }
    if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
        for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
            print!("  ");
        }
    }
    println!(" {}", output);
}

pub struct Analyzer<'a> {
    il2cpp: &'a Il2Cpp,
    exe_base: u64,
    virtual_memory: Vec<u8>,
}

impl<'a> Analyzer<'a> {
    pub fn new(il2cpp: &'a Il2Cpp, exe: &[u8]) -> Result<Self> {
        let pe = PeFile64::parse(&*exe)?;
        let exe_base = pe.relative_address_base();

        let nt_headers = pe.nt_headers();
        let size_of_image = nt_headers.optional_header.size_of_image.get(LittleEndian) as usize;

        let mut virtual_memory = vec![0u8; size_of_image];

        let size_of_headers = nt_headers.optional_header.size_of_headers.get(LittleEndian) as usize;
        let header_copy_len = std::cmp::min(size_of_headers, exe.len());
        virtual_memory[..header_copy_len].copy_from_slice(&exe[..header_copy_len]);

        for section in pe.sections() {
            let rva = (section.address() - exe_base) as usize;
            if let Ok(data) = section.data() {
                let copy_len = std::cmp::min(data.len(), virtual_memory.len() - rva);
                virtual_memory[rva..rva + copy_len].copy_from_slice(&data[..copy_len]);
            }
        }
        Ok(Self {
            il2cpp,
            exe_base,
            virtual_memory
        })
    }

    fn to_rva(&self, addr: u64) -> usize {
        to_rva_from_base(addr, self.exe_base)
    }

    #[deprecated(note="use find_static_from_getter instead")]
    fn find_singleton(&self, ty: &REType) -> Option<(u64, String)> {
        let mut decoder = Decoder::new(64, &self.virtual_memory, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        formatter.options_mut().set_first_operand_char_index(10);
        let mut output = String::new();

        for method in ty.methods.values() {
            let method_name = method.name.replace(&method.id.to_string(), "");
            if method_name == "get_Instance" && method.flags.contains(&REMethodFlag::Static) {
                let addr = method.function;
                let rva = self.to_rva(addr);
                decoder.set_position(rva).ok()?;
                decoder.set_ip(addr);

                //println!("Found singleton {}", ty.name);
                let mut instruction = Instruction::new();
                while decoder.can_decode() {
                    decoder.decode_out(&mut instruction);
                    output.clear();
                    //let current_rva = rva + (instruction.ip() - addr) as usize;
                    //let instr_bytes = &self.virtual_memory[current_rva..current_rva + instruction.len()];
                    //print_instruction(&mut output, &mut instruction, instr_bytes, &mut formatter);

                    if let Some(ptr) = is_mov_ret_reg_ptr(&instruction) {
                        if let Some(return_type) = &method.returns {
                            // println!("[INFO] Found singleton pointer at: {:016X} of type {}", global_ptr, return_type.r#type);
                            return Some((ptr, return_type.r#type.clone()));
                        }
                    }

                    if instruction.flow_control() != FlowControl::Next {
                        break;
                    }
                }
            }
        }
        None
    }

    fn find_native_singleton(&self, ty: &REType) -> Option<u64> {
        let mut decoder = Decoder::new(64, &self.virtual_memory, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        formatter.options_mut().set_first_operand_char_index(10);
        let mut output = String::new();

        for method in ty.methods.values() {
            let method_name = method.name.replace(&method.id.to_string(), "");
            if method_name == "hasInstance" {

                let addr = method.function;
                let rva = self.to_rva(addr);
                decoder.set_position(rva).ok()?;
                decoder.set_ip(addr);

               // println!("Found native singleton {} with hasInstance", ty.name);
                let mut instruction = Instruction::new();
                while decoder.can_decode() {
                    decoder.decode_out(&mut instruction);
                    output.clear();
                    //let current_rva = rva + (instruction.ip() - addr) as usize;
                    //let instr_bytes = &self.virtual_memory[current_rva..current_rva + instruction.len()];
                    //print_instruction(&mut output, &mut instruction, instr_bytes, &mut formatter);

                    if let Some(global_ptr) = is_ptr_null_check(&instruction) {
                        return Some(global_ptr)
                    }
                    if instruction.flow_control() != FlowControl::Next {
                        break;
                    }
                }
            }
        }
        None
    }

    pub fn find_singletons(&self) -> HashMap<String, u64> {
        let mut singletons = HashMap::new();
        for (_, ty) in self.il2cpp {
            // native singletons
            if ty.name.starts_with("via.") {
                let singleton_ptr = self.find_native_singleton(ty);
                if let Some(singleton) = singleton_ptr {
                    singletons.insert(ty.name.clone(), singleton);
                }
            }

            // other singletons (NOTE: these are also found in find_static_fields, can probably remove)
            if let Some(instance_field) = ty.fields.values().find(|f| f.name.as_str() == "_Instance") {
                if instance_field.flags.contains(&REFieldFlag::Static) {
                    if let Some((singleton, ty_name)) = self.find_singleton(ty) {
                        singletons.insert(ty_name, singleton);
                    }
                }
            }
        }
        singletons
    }

    pub fn find_native_singletons(&self) -> HashMap<String, u64> {
        let mut singletons = HashMap::new();
        for (_, ty) in self.il2cpp {
            // native singletons
            if ty.name.starts_with("via.") {
                let singleton_ptr = self.find_native_singleton(ty);
                if let Some(singleton) = singleton_ptr {
                    singletons.insert(ty.name.clone(), singleton);
                }
            }
        }
        singletons
    }

    // NOTE: not sure if there can ever be a pointer deref and then getting the static field from there
    // i don't think those fields would actually be static if that was the case
    /* I think it's possible for some static to not be set, so the game might first try to check
     * if it exists with a null check, and then an initialize if null
     * for example (from mhrise):
     * result = (snow_telemetry_kpi_Amiibo *)qword_7FF6B06FBF48;
     * if ( !qword_7FF6B06FBF48 ) {
     *     ...
     * }

     * The instructions for this probably look like this, don't know how consistent it would be,
     * seg000:00007FF6A1825FE0                 sub     rsp, 28h
     * seg000:00007FF6A1825FE4                 mov     rax, cs:qword_7FF6B06FBF48
     * seg000:00007FF6A1825FEB                 test    rax, rax
     */
    pub fn find_static_from_getter(&self, method: &REMethod) -> Option<u64> {
        let mut decoder = Decoder::new(64, &self.virtual_memory, DecoderOptions::NONE);

        let addr = method.function;
        let rva = self.to_rva(addr);
        decoder.set_position(rva).ok()?;
        decoder.set_ip(addr);

        let mut it = decoder.iter();
        // hopefully the mov rax [rel foo] is somewhere in the first 10 instructions, otherwise its
        // probably too complex to look for
        for _ in 0..10 {
            let instruction = it.next()?;
            if let Some(res) = is_mov_ret_reg_ptr(&instruction) {
                return Some(res);
            }

            // maybe a cmp qword [rel foo], 0 could happen
            if let Some(res) = is_ptr_null_check(&instruction) {
                return Some(res);
            }

            // cooked idk
            if instruction.flow_control() != FlowControl::Next {
                return None;
            }
        }

        None
    }

    pub fn find_static_fields(&self) -> HashMap<String, HashMap<String, (u64, String)>> {
        let mut static_fields = HashMap::new();
        for (_, ty) in self.il2cpp {
            let methods = ty.methods.values()
                .filter(|m| m.flags.contains(&REMethodFlag::Static) 
                    && m.name.starts_with("get"));
            let mut ty_statics = HashMap::new();
            for method in methods {
                let field_name = method.name.replace(&method.id.to_string(), "").replace("get", "");
                let Some(ref ret_type) = method.returns else { continue };
                if let Some(field) = ty.fields.get(&field_name) {
                    //println!("Checking {}::{} using method {}", ty.name, field_name, method.name);
                    // just to make sure
                    if field.flags.contains(&REFieldFlag::Static) {
                        if let Some(addr) = self.find_static_from_getter(&method) {
                            ty_statics.insert(field_name, (addr, ret_type.r#type.to_string()));
                        } else {
                            //println!("Failed to find {field-}");
                            println!("Failed finding {}::{} using method {}", ty.name, field_name, method.name);
                        }
                    }
                }
            }
            if !ty_statics.is_empty() {
                static_fields.insert(ty.name.clone(), ty_statics);
            }
        }
        static_fields
    }
}

pub fn is_return_reg(reg: Register) -> bool {
    matches!(reg, Register::AL | Register::AX | Register::EAX | Register::RAX)
}

pub fn is_mov_ret_reg_ptr(instruction: &Instruction) -> Option<u64> {
    if instruction.mnemonic() == Mnemonic::Mov {
        if instruction.op0_kind() == OpKind::Register 
            && is_return_reg(instruction.op0_register()) {
                if instruction.op1_kind() == OpKind::Memory && instruction.is_ip_rel_memory_operand() {
                    return Some(instruction.ip_rel_memory_address());
                }
            }
    } 
    None
}

pub fn is_ptr_null_check(instruction: &Instruction) -> Option<u64> {
    if instruction.mnemonic() == Mnemonic::Cmp {
        if instruction.op0_kind() == OpKind::Memory && instruction.is_ip_rel_memory_operand() {
            let is_zero = match instruction.op1_kind() {
                OpKind::Immediate8 => instruction.immediate8() == 0,
                OpKind::Immediate8to16 => instruction.immediate8to16() == 0,
                OpKind::Immediate8to32 => instruction.immediate8to32() == 0,
                OpKind::Immediate8to64 => instruction.immediate8to64() == 0,
                OpKind::Immediate16 => instruction.immediate16() == 0,
                OpKind::Immediate32 => instruction.immediate32() == 0,
                OpKind::Immediate32to64 => instruction.immediate32to64() == 0,
                OpKind::Immediate64 => instruction.immediate64() == 0,
                _ => false,
            };
            if is_zero {
                return Some(instruction.ip_rel_memory_address());
            }
        }
    } 
    None
}

pub fn to_rva_from_base(addr: u64, exe_base: u64) -> usize {
    let rva = if addr >= exe_base {
        (addr - exe_base) as usize
    } else if addr >= 0x140000000 {
        (addr - 0x140000000) as usize
    } else {
        addr as usize
    };
    rva
}


