use std::fs;

use iced_x86::{Decoder, FlowControl, Formatter, Instruction, OpKind, Register};

use ree_pdb::analyzer::Analyzer;
use ree_pdb::il2cpp::{deserialize_il2cpp};
use clap::Parser;
use anyhow::{Result};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = "il2cpp_dump.json", help = "path to il2cpp dump")]
    il2cpp: String,
    #[arg(short, long, help = "path to the dumped game exe")]
    exe: String,
    #[arg(short, long, help = "path to output")]
    output: Option<String>,
}


pub fn disassemble_function<'a, F: Formatter>(
    display_addr: u64, 
    rva: usize, 
    virtual_memory: &'a [u8], 
    decoder: &'a mut Decoder, 
    formatter: &mut F
) -> Result<()> {
    decoder.set_position(rva)?;
    decoder.set_ip(display_addr);

    let mut instruction = Instruction::default();
    let mut output = String::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);

        let current_rva = rva + (instruction.ip() - display_addr) as usize;
        let instr_bytes = &virtual_memory[current_rva..current_rva + instruction.len()];

        //print!("{:016X} ", instruction.ip());

        /*for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }

        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                print!("  ");
            }
        }
        println!(" {}", output);*/

        if instruction.mnemonic() == iced_x86::Mnemonic::Mov {
            // Check if the source (operand 1) is a memory read
            if instruction.op1_kind() == OpKind::Memory {

                let base_reg = instruction.memory_base();
                let offset = instruction.memory_displacement32();

                // Ignore the RIP-relative global read, look for struct dereferences
                if base_reg != Register::RIP && base_reg != Register::None {
                    println!("Found struct read at offset: {:#X} (Base: {:?})", offset, base_reg);
                }
            }
        }

        if instruction.flow_control() == FlowControl::Return {
            break;
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    let args = Args::parse();
    println!("[INFO] Loading il2cpp from {}", args.il2cpp);
    let il2cpp_str = std::fs::read_to_string(&args.il2cpp)?;
    let mut deserializer = serde_json::Deserializer::from_str(&il2cpp_str);
    let il2cpp = deserialize_il2cpp(&mut deserializer)?;

    let bytes = fs::read(&args.exe)?;

    println!("[INFO] Mapping exe to vec");


    let analyzer = Analyzer::new(&il2cpp, &bytes)?;
    let singletons = analyzer.find_singletons();
    println!("{:#?}", singletons);
    /*let ty = &il2cpp["via.storage.saveService.SaveService"];
    //let method = &ty.methods["get_SaveDataSize764593"];


    for (name, method) in &ty.methods {
        if !name.contains("get_") {
            continue
        }

        let addr = method.function;
        //println!("disassembling {name}@{:016X} (Mapped RVA Index: {:#X})", addr, rva);
        //disassemble_function(addr, rva, &virtual_memory, &mut decoder, &mut formatter)?;

    }*/

    Ok(())
}
