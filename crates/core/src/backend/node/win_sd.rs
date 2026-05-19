//! Windows security-descriptor capture/apply (kopia-0dr.39 inc 2a).
//!
//! Captures a file's whole self-relative security descriptor on backup
//! and re-applies it on restore. Carried in `Metadata.generic_attributes`
//! under restic's `"windows.security_descriptor"` key, value = base64
//! of the raw SD (restic-compatible encoding).
#![cfg(windows)]
#![allow(unsafe_code)] // Win32 FFI; sealed inside `capture` / `apply`.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use base64::Engine as _;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorLength,
    GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, ACL, DACL_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SACL_SECURITY_INFORMATION,
};

/// The restic `GenericAttributeType` key for the security descriptor.
pub const SD_KEY: &str = "windows.security_descriptor";

/// owner + group + DACL + SACL.
const ALL_SD_INFO: u32 = OWNER_SECURITY_INFORMATION
    | GROUP_SECURITY_INFORMATION
    | DACL_SECURITY_INFORMATION
    | SACL_SECURITY_INFORMATION;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Capture `path`'s self-relative security descriptor, base64-encoded.
/// Best-effort: returns `None` on any failure (e.g. SACL denied
/// without `SeSecurityPrivilege`) — the caller logs and continues.
pub fn capture(path: &Path) -> Option<String> {
    // SACL is best-effort: try the full SD, then fall back without it.
    capture_with(path, ALL_SD_INFO)
        .or_else(|| capture_with(path, ALL_SD_INFO & !SACL_SECURITY_INFORMATION))
}

fn capture_with(path: &Path, info: u32) -> Option<String> {
    let w = wide(path);
    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut psd,
        );
        if rc != ERROR_SUCCESS || psd.is_null() {
            return None;
        }
        // psd is a self-relative SD allocated by the API; copy it out.
        let len = GetSecurityDescriptorLength(psd) as usize;
        let bytes = std::slice::from_raw_parts(psd as *const u8, len).to_vec();
        LocalFree(psd as _);
        Some(base64::engine::general_purpose::STANDARD.encode(bytes))
    }
}

/// Apply a base64-encoded self-relative security descriptor to `path`.
/// Best-effort; returns false if decode or the core apply failed.
pub fn apply(path: &Path, b64_sd: &str) -> bool {
    let Ok(sd) = base64::engine::general_purpose::STANDARD.decode(b64_sd) else {
        return false;
    };
    let w = wide(path);
    unsafe {
        let psd = sd.as_ptr() as PSECURITY_DESCRIPTOR;
        let mut owner = ptr::null_mut();
        let mut group = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        let mut present = 0;
        GetSecurityDescriptorOwner(psd, &mut owner, &mut defaulted);
        GetSecurityDescriptorGroup(psd, &mut group, &mut defaulted);
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted);
        GetSecurityDescriptorSacl(psd, &mut present, &mut sacl, &mut defaulted);
        let rc = SetNamedSecurityInfoW(
            w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            ALL_SD_INFO,
            owner,
            group,
            dacl,
            sacl,
        );
        rc == ERROR_SUCCESS
    }
}
