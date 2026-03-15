use anyhow::{anyhow, Result};
use std::mem;
pub use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Information about a running process
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// Lists all running processes
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to create process snapshot"));
        }

        let mut processes = Vec::new();
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                });

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot)?;
        Ok(processes)
    }
}

/// Opens a process with necessary permissions for memory scanning
pub fn open_process(pid: u32) -> Result<HANDLE> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
            false,
            pid,
        )?;

        if handle.is_invalid() {
            return Err(anyhow!("Failed to open process {}", pid));
        }

        Ok(handle)
    }
}

/// Closes a process handle
pub fn close_process(handle: HANDLE) -> Result<()> {
    unsafe {
        CloseHandle(handle)?;
        Ok(())
    }
}

/// Information about a memory region
#[derive(Clone, Debug)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

impl MemoryRegion {
    /// Creates MemoryRegion from MEMORY_BASIC_INFORMATION
    fn from_mbi(mbi: &MEMORY_BASIC_INFORMATION) -> Self {
        let protection = mbi.Protect.0;
        let is_readable = matches!(
            mbi.Protect,
            PAGE_READONLY
                | PAGE_READWRITE
                | PAGE_WRITECOPY
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_READWRITE
                | PAGE_EXECUTE_WRITECOPY
        );
        let is_writable = matches!(
            mbi.Protect,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );
        let is_executable = matches!(
            mbi.Protect,
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );

        Self {
            base_address: mbi.BaseAddress as usize,
            size: mbi.RegionSize,
            protection,
            state: mbi.State.0,
            is_readable,
            is_writable,
            is_executable,
        }
    }
}

/// Queries all memory regions of a process
pub fn query_memory_regions(handle: HANDLE) -> Result<Vec<MemoryRegion>> {
    unsafe {
        let mut regions = Vec::new();
        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();

        loop {
            let result = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            // Only include committed memory regions
            if mbi.State == MEM_COMMIT {
                regions.push(MemoryRegion::from_mbi(&mbi));
            }

            address = (mbi.BaseAddress as usize) + mbi.RegionSize;

            // Prevent overflow
            if address == 0 {
                break;
            }
        }

        Ok(regions)
    }
}

/// Reads memory from a process
pub fn read_process_memory(handle: HANDLE, address: usize, size: usize) -> Result<Vec<u8>> {
    unsafe {
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        let success = ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        );

        if success.is_err() || bytes_read != size {
            return Err(anyhow!(
                "Failed to read memory at 0x{:X} (size: {})",
                address,
                size
            ));
        }

        Ok(buffer)
    }
}

/// Writes memory to a process
pub fn write_process_memory(handle: HANDLE, address: usize, data: &[u8]) -> Result<()> {
    unsafe {
        let mut bytes_written = 0;

        let success = WriteProcessMemory(
            handle,
            address as *const _,
            data.as_ptr() as *const _,
            data.len(),
            Some(&mut bytes_written),
        );

        if success.is_err() || bytes_written != data.len() {
            return Err(anyhow!("Failed to write memory at 0x{:X}", address));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let processes = list_processes().expect("Failed to list processes");
        assert!(!processes.is_empty(), "Should find at least one process");

        // Check if current process is in the list
        let current_pid = std::process::id();
        let found = processes.iter().any(|p| p.pid == current_pid);
        assert!(found, "Current process should be in the list");
    }
}
