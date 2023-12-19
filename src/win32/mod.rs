use core::ffi::c_void;
use std::mem::transmute;

use windows::{
    core::{s, PCWSTR},
    core::{w, PCSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, BOOLEAN, HANDLE, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH,
            UNICODE_STRING,
        },
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        Storage::FileSystem::{CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_NO_SERIALIZE, HEAP_ZERO_MEMORY},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
};

#[derive(Copy, Clone)]
pub struct NTAdresses {
    pub nt_query_system_information: FnNtQuerySystemInformation,
    pub rtl_init_unicode_string: FnRtlInitUnicodeString,
}

impl NTAdresses {
    fn new(
        nt_query_system_information: FnNtQuerySystemInformation,
        rtl_init_unicode_string: FnRtlInitUnicodeString,
    ) -> NTAdresses {
        NTAdresses {
            nt_query_system_information,
            rtl_init_unicode_string,
        }
    }

    pub fn build() -> Result<NTAdresses, &'static str> {
        let ntdll_handle;
        match unsafe { GetModuleHandleW(w!("ntdll")) } {
            Ok(n) => ntdll_handle = n,
            Err(_) => return Err("Could not get handle to ntdll"),
        };
        let nt_query_system_information_address;
        match unsafe { GetProcAddress(ntdll_handle, s!("NtQuerySystemInformation")) } {
            Some(x) => nt_query_system_information_address = x,
            None => return Err("Could find NtQuerySystemInformation"),
        }

        let ntquery_system_information: FnNtQuerySystemInformation =
            unsafe { transmute(nt_query_system_information_address) };

        let rtl_init_unicode_string_address;
        match unsafe { GetProcAddress(ntdll_handle, s!("RtlInitUnicodeString")) } {
            Some(x) => rtl_init_unicode_string_address = x,
            None => return Err("Could find RtlInitUnicodeString"),
        }
        let rtl_init_unicode_string: FnRtlInitUnicodeString =
            unsafe { transmute(rtl_init_unicode_string_address) };

        return Ok(NTAdresses::new(
            ntquery_system_information,
            rtl_init_unicode_string,
        ));
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SystemHandleTableEntryInfo {
    pub processid: u32,
    pub object_type_number: u8,
    pub flags: u8,
    pub handle: u16,
    pub object: *mut c_void,
    pub granted_access: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SystemHandleInformation {
    pub number_of_handles: u32,
    pub handles: [SystemHandleTableEntryInfo; 1], //Taken from official Win32 doc ARRAY_ANYSIZE = 1 https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges#members
}

type FnNtQuerySystemInformation = extern "stdcall" fn(i32, *mut c_void, u32, *mut u32) -> NTSTATUS;
type FnRtlInitUnicodeString = extern "system" fn(*mut UNICODE_STRING, PCWSTR) -> BOOLEAN;

pub fn set_debug_privilege() -> Result<bool, &'static str> {
    let mut h_token = HANDLE::default();
    // These returning results always evaluate to Ok(), thus GetLastError was used
    unsafe {
        _ = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut h_token,
        );
    }

    let mut tokenprivileges: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES::default();
    tokenprivileges.PrivilegeCount = 1;
    tokenprivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    unsafe {
        _ = LookupPrivilegeValueW(
            None,
            w!("SeDebugPrivilege"),
            &mut tokenprivileges.Privileges[0].Luid,
        );
        if !GetLastError().is_ok() {
            return Err("Could not LookupPrivilegeValueW");
        }
    }

    unsafe {
        _ = AdjustTokenPrivileges(
            h_token,
            false,
            Some(&mut tokenprivileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );

        if !GetLastError().is_ok() {
            return Err("Could not AdjustTokenPrivileges");
        }
    };

    unsafe { _ = CloseHandle(h_token) };

    Ok(true)
}

fn reallocate_handle_infotable_size(
    ultable_size: usize,
) -> Result<*mut SystemHandleInformation, &'static str> {
    let hheap: HANDLE;
    unsafe {
        match GetProcessHeap() {
            Ok(n) => hheap = n,
            Err(_) => return Err("Could not get process heap"),
        }
    };
    unsafe {
        if let Err(_) = HeapFree(hheap, HEAP_NO_SERIALIZE, None) {
            return Err("Error when calling HeapFree");
        }
    };

    unsafe {
        return Ok(HeapAlloc(hheap, HEAP_ZERO_MEMORY, ultable_size) as *mut SystemHandleInformation);
    }
}

pub fn connect_to_device(devicename: &'static str) -> Result<HANDLE, String> {
    let device: HANDLE;
    unsafe {
        match CreateFileA(
            PCSTR(devicename.as_ptr()),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(n) => device = n,
            Err(_) => return Err("Could not connect to device ".to_owned() + devicename),
        }
    };

    return Ok(device);
}

pub fn get_object_address_from_handle(
    pid: u32,
    handle: u16,
    addresses: &NTAdresses,
) -> Result<*mut c_void, &'static str> {
    let handle_table_information = get_handle_information_table(&addresses)?;

    let table_information;
    match unsafe { handle_table_information.as_ref() } {
        Some(x) => table_information = x,
        None => return Err("Could not cast table information"),
    }

    let num_handles = table_information.number_of_handles;
    let mut table_information_handles_ptr = table_information.handles.as_ptr();
    for _ in 0..num_handles {
        let handle_info = unsafe { *table_information_handles_ptr };
        if handle_info.processid == pid && handle_info.handle == handle {
            return Ok(handle_info.object);
        }
        table_information_handles_ptr = unsafe { table_information_handles_ptr.add(1) };
    }

    Err("Could not find address for handle")
}

pub fn get_handle_information_table(
    addresses: &NTAdresses,
) -> Result<*mut SystemHandleInformation, &'static str> {
    let mut system_info_length: usize = std::mem::size_of::<SystemHandleInformation>()
        + (std::mem::size_of::<SystemHandleTableEntryInfo>() * 100)
        - 2300;
    let mut handle_informationtable = reallocate_handle_infotable_size(system_info_length)?;
    // 16 = CONST_SYSTEM_HANDLE_INFORMATION
    let mut status = (addresses.nt_query_system_information)(
        16,
        handle_informationtable as *mut c_void,
        system_info_length as u32,
        &mut 0,
    );

    while status == STATUS_INFO_LENGTH_MISMATCH {
        system_info_length *= 2;
        handle_informationtable = reallocate_handle_infotable_size(system_info_length)?;
        status = (addresses.nt_query_system_information)(
            16,
            handle_informationtable as *mut c_void,
            system_info_length as u32,
            &mut 0,
        );
    }

    if status != NTSTATUS(0) {
        return Err("Could not find handleInformationTable");
    }

    return Ok(handle_informationtable);
}
