extern crate capstone;
use crate::list::emu_report;
use capstone::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use unicorn_engine::unicorn_const::{uc_error, Arch, Mode, Permission};
use unicorn_engine::{RegisterX86, Unicorn};

pub const IMAGE_BASE: u64 = 0x400000;
pub const STACK_BASE: u64 = 0x1000000;
pub const STACK_SIZE: usize = 0x00250000;

#[derive(Debug, Copy, Clone)]
pub struct RegState {
    pub reg: [u64; RegisterX86::ENDING as usize],
}

impl RegState {
    fn from_emu<D>(emu: &Unicorn<D>) -> Self {
        use unicorn_engine::RegisterX86::*;
        let mut reg: [u64; ENDING as usize] = [0; ENDING as usize];
        macro_rules! get_reg {
            ($r:expr) => {{
                reg[$r as usize] = emu.reg_read($r).unwrap();
            }};
        }
        get_reg!(EAX);
        get_reg!(EBX);
        get_reg!(ECX);
        get_reg!(EDX);
        get_reg!(EDI);
        get_reg!(ESI);
        get_reg!(EIP);
        get_reg!(ESP);
        get_reg!(EBP);
        get_reg!(EFLAGS);

        RegState { reg }
    }
}

#[derive(Clone)]
pub struct Instruction {
    pub mnemonic: String,
    pub operands: String,
    pub address: u32,
}

impl Instruction {
    fn new(mnemonic: String, operands: String, address: u32) -> Instruction {
        Instruction {
            mnemonic,
            operands,
            address,
        }
    }
}

#[derive(Clone)]
pub struct EmuState {
    pub instruction: Instruction,
    pub reg_state: RegState,
}

impl EmuState {
    fn new(instruction: Instruction, reg_state: RegState) -> Self {
        EmuState {
            instruction,
            reg_state,
        }
    }
}

pub struct EmuReport {
    pub state: Vec<EmuState>, 
    cs: capstone::Capstone,
}

impl EmuReport {
    fn new() -> Self {
        EmuReport { 
            state: Vec::new(),
            cs: Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create capstone"),
        }
    }
}

fn get_virtual_mapping(file_name: impl AsRef<Path>) -> Vec<u8> {
    let mut pe_file = File::open(file_name.as_ref())
        .expect("Failed to open file");
    let mut pe: Vec<u8> = Vec::new();
    pe_file.read_to_end(&mut pe).unwrap();

    let mut vmem: Vec<u8> = vec![0; 1024 * 1024 * 2];

    let text_section = &pe[0x400..0x2A00 + 0x400];
    map_to_vmem(&mut vmem, text_section, 0x1000);

    let vm_section = &pe[0x2E00..0x1400 + 0x2E00];
    map_to_vmem(&mut vmem, vm_section, 0x4000);

    let rdata_section = &pe[0x4200..0x4200 + 0x1200];
    map_to_vmem(&mut vmem, rdata_section, 0x6000);

    let data_section = &pe[0x5400..0x5400 + 0x200];
    map_to_vmem(&mut vmem, data_section, 0x8000);

    let vmrun_section = &pe[0x5600..0x5600 + 0x10A00];
    map_to_vmem(&mut vmem, vmrun_section, 0x9000);

    let pcode_section = &pe[0x16000..0x16000 + 0x800];
    map_to_vmem(&mut vmem, pcode_section, 0x1A000);

    let tlsrun_section = &pe[0x16800..0x16800 + 0x10200];
    map_to_vmem(&mut vmem, tlsrun_section, 0x1B000);

    let rsrc_section = &pe[0x26A00..0x26A00 + 0x200];
    map_to_vmem(&mut vmem, rsrc_section, 0x2C000);

    let reloc_section = &pe[0x26C00..0x26C00 + 0x600];
    map_to_vmem(&mut vmem, reloc_section, 0x2D000);

    vmem
}

fn map_to_vmem(vmem: &mut Vec<u8>, section: &[u8], vaddr: usize) {
    vmem.splice(vaddr..vaddr, section.iter().copied()); //this is slow af
}

pub fn emulate(file_path: impl AsRef<Path>, address: u64) {
    let emu_report = EmuReport::new();
    let mut emu = Unicorn::new_with_data(Arch::X86, Mode::MODE_32, emu_report).unwrap();

    let vmap = get_virtual_mapping(file_path);
    emu.mem_map(IMAGE_BASE, 1024 * 1024 * 4, Permission::ALL)
        .expect("Failed to map vmem");
    emu.mem_write(IMAGE_BASE, &vmap)
        .expect("Failed to write pe");
    emu.mem_map(STACK_BASE, STACK_SIZE, Permission::ALL)
        .expect("Failed to map stack");
    emu.mem_write(STACK_BASE, &[0; STACK_SIZE])
        .expect("Failed to fill stack with zeros");

    emu.reg_write(RegisterX86::ESP, STACK_BASE + 0x800).unwrap();
    emu.reg_write(RegisterX86::EBP, STACK_BASE + 0x1000)
        .unwrap();

    emu.reg_write(RegisterX86::EBX, 0).unwrap();
    emu.reg_write(RegisterX86::ECX, 0).unwrap();
    emu.reg_write(RegisterX86::EDX, 0).unwrap();

    emu.add_code_hook(IMAGE_BASE, IMAGE_BASE + 1024 * 1024 * 2, &hook_code)
        .expect("Failed to add code hook");

    //0x00401F8C
    match emu.emu_start(address, 0x0, 0, 0) {
        Ok(()) => println!("Execution went okay lmao"),
        Err(err) => handle_emu_error(&mut emu, err),
    };
}

fn handle_emu_error(emu: &mut Unicorn<EmuReport>, _error: uc_error) {
    
    emu_report(emu.get_data()).unwrap();
}

fn dissasm_at_address(emu: &mut Unicorn<EmuReport>, address: u64, size: usize) -> Instruction {
    let cs = &emu.get_data().cs;
    let code_buf = emu
        .mem_read_as_vec(address, size)
        .unwrap();
    let insns = cs.disasm_all(&code_buf, 0).unwrap();
    let first_ins = insns.first().unwrap();
    let (mnemonic, operands) = (first_ins.mnemonic().unwrap(),
                                    first_ins.op_str().unwrap());
    Instruction::new(mnemonic.to_owned(),
    operands.to_owned(),
    address.try_into().unwrap())
}

fn hook_code(emu: &mut Unicorn<EmuReport>, address: u64, size: u32) {
    let ins = dissasm_at_address(emu, address, size as usize); 
    let reg_state = RegState::from_emu(emu);
    let emu_state = EmuState::new(ins, reg_state);
    emu.get_data_mut().state.push(emu_state);
}
