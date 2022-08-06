mod emu;
mod list;
use std::env;
use emu::emulate;

fn usage() {
    println!("remu [file] [entry address]");
}

fn main() {
    if env::args().len() < 3 {
        usage();
        return;
    }
    let file: String = env::args().nth(1).unwrap();
    let address: String = env::args().nth(2).unwrap();
    let address = if let Some(stripped) = address.strip_prefix("0x") {
        u64::from_str_radix(&stripped, 16).unwrap()
    } else {
        u64::from_str_radix(&address, 16).unwrap()
    };

    emulate(file, address);
}
