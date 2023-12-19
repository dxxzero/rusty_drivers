use crate::DriverBuilder;

use self::{process_explorer::ProcExp, genshin::Genshin, rentdrv2::RentDrv2, true_sight::TrueSight};

pub mod genshin;
pub mod process_explorer;
pub mod rentdrv2;
pub mod true_sight;

pub fn run(pid: u32, driver: String) -> Result<Box<dyn DriverBuilder>, String> {
    if driver == "process_explorer" {
        return ProcExp::build(pid)
    } else if driver == "genshin" {
        return Genshin::build(pid)
    } else if driver == "rentdrv2" {
        return RentDrv2::build(pid)
    } else if driver == "truesight" {
        return TrueSight::build(pid)
    } else {
        return Err("Driver is not supported".into());
    };
}