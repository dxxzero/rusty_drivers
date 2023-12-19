use rusty_drivers::{Args, run};
use clap::Parser;

pub mod win32;


fn main() {
    let config = Args::parse();

    println!("Got PID {}", config.pid);
    println!("Using driver {}", config.driver);

    if let Err(e) = run(config) {
        println!("Application error: {e}");
    }
}
