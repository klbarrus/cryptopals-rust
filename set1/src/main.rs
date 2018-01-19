extern crate cp16;

use std::env;
use std::process;
use cp16::Config;

fn main() {
    let args: Vec<String> = env::args().collect();
    let config = Config::new(&args).unwrap_or_else(|err| {
        println!("{}", err);
        show_usage(&args[0]);
        process::exit(1);
    });

    if let Err(e) = cp16::run(config) {
        println!("Application error: {}", e);
        process::exit(1);
    }
}

fn show_usage(prog_name: &String) {
    println!("Break repeating-key XOR - set 1 challenge 6.");
    println!("");
    println!("Usage:");
    println!("  {}", prog_name);
    println!("    Break repeating-key XOR");
}