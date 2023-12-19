use std::error::Error;
use clap::Parser;
use crate::win32::set_debug_privilege;

pub mod drivers;
pub mod win32;

pub fn run(config: Args) -> Result<(), Box<dyn Error>> {
    set_debug_privilege()?;

    let p = drivers::run(config.pid, config.driver)?;

    p.kill()?;

    println!("Process with PID {} killed", config.pid);

    Ok(())
}

pub trait DriverBuilder {
    fn build(pid: u32) -> Result<Box<dyn DriverBuilder>, String>
    where
        Self: Sized;
    fn kill(&self) -> Result<(), String>;
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub pid: u32,
    #[arg(short, long)]
    pub driver: String,
}
