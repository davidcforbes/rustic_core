//! NTFS reparse-point capture + restore (kopia-4rf —
//! rustback-filecopy increment 2c).
//!
//! NTFS reparse points are the filesystem's pluggable-extension
//! mechanism. The host file or directory carries an opaque blob plus
//! a 32-bit `IO_REPARSE_TAG_*` value identifying the consumer:
//!
//! | Tag | Hex | What carries it |
//! |---|---|---|
//! | `IO_REPARSE_TAG_MOUNT_POINT` | `0xA0000003` | Junctions, volume mount points |
//! | `IO_REPARSE_TAG_SYMLINK`     | `0xA000000C` | Symbolic links |
//! | `IO_REPARSE_TAG_WOF`         | `0x80000017` | Compact-OS-compressed system files |
//! | `IO_REPARSE_TAG_CLOUD_*`     | `0x9000_X01A` | OneDrive Files-On-Demand placeholders (instance nibble at bits 12-15) |
//! | `IO_REPARSE_TAG_APPEXECLINK` | `0x8000001B` | UWP execution aliases |
//!
//! Only `MOUNT_POINT` and `SYMLINK` have published wire structures
//! (`REPARSE_DATA_BUFFER.MountPointReparseBuffer` /
//! `SymbolicLinkReparseBuffer`); MS-FSCC § 2.1.2.1 mandates that
//! clients treat all other tags' data as opaque. This module
//! honours that — capture pulls the raw `REPARSE_DATA_BUFFER` body
//! (the bytes following the 8-byte fixed header) and apply pushes
//! it back verbatim. No tag-specific interpretation happens in this
//! module; classification (junction-vs-symlink-vs-other) is the
//! caller's job in `ignore::mapper`.
//!
//! Three primitives:
//!
//! 1. [`is_reparse_point`] — query the `FILE_ATTRIBUTE_REPARSE_POINT`
//!    bit via `GetFileAttributesExW`. Cheap predicate the walker
//!    uses to short-circuit normal File/Dir/Symlink classification.
//! 2. [`read_tag`] — one `GetFileInformationByHandleEx(FileAttributeTagInfo)`
//!    syscall, no 16 KB allocation. Used by the walker when it
//!    just needs to classify (e.g., to skip junction recursion)
//!    without pulling the full body.
//! 3. [`capture`] / [`apply`] — full round-trip via
//!    `FSCTL_GET_REPARSE_POINT` / `FSCTL_SET_REPARSE_POINT`.
//!    `capture` returns `(tag, body)`; `apply` rebuilds the full
//!    buffer (header + body) from the same pair.
//!
//! Also [`is_cloud_tag`] — a small predicate that recognises the
//! `IO_REPARSE_TAG_CLOUD_*` family (16 instance variants sharing a
//! masked-equality with `0x9000_001A`).
//!
//! All four are best-effort: failures bubble as `io::Error`, the
//! caller logs and continues rather than aborting.

#![cfg(windows)]
#![allow(unsafe_code)] // Win32 FFI; sealed inside this module.

use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesExW, GetFileExInfoStandard, FileAttributeTagInfo,
    GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA,
    MAXIMUM_REPARSE_DATA_BUFFER_SIZE, OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA,
};
use windows_sys::Win32::System::Ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// `Metadata.generic_attributes` key under which captured reparse
/// blobs land. Carrying it as a constant keeps the two ends of the
/// pipe in sync (capture in `mapper.rs`, apply in
/// `local_destination.rs`).
pub const REPARSE_KEY: &str = "windows.reparse_point";

/// `IO_REPARSE_TAG_MOUNT_POINT` — junctions / volume mount points.
pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK` — symbolic links (file or directory).
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// 8-byte fixed `REPARSE_DATA_BUFFER` header: `ReparseTag` (u32) +
/// `ReparseDataLength` (u16) + `Reserved` (u16). The wire-format
/// `data` field carries only the bytes that follow this header.
const REPARSE_HEADER_SIZE: usize = 8;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Returns `true` if `path`'s `FILE_ATTRIBUTE_REPARSE_POINT` bit is
/// set. `GetFileAttributesExW` does NOT follow reparse points, so
/// this works for any reparse-tagged file or directory.
pub fn is_reparse_point(path: &Path) -> io::Result<bool> {
    let w = wide(path);
    // SAFETY: `w` is a NUL-terminated UTF-16 buffer we own; `data`
    // is a stack-allocated POD struct written by the API.
    unsafe {
        let mut data: WIN32_FILE_ATTRIBUTE_DATA = mem::zeroed();
        let ok = GetFileAttributesExW(
            w.as_ptr(),
            GetFileExInfoStandard,
            ptr::from_mut::<WIN32_FILE_ATTRIBUTE_DATA>(&mut data).cast(),
        );
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
}

/// Returns `true` iff `tag` is in the `IO_REPARSE_TAG_CLOUD_*`
/// family. The family covers 16 instance variants (`CLOUD_0` ..
/// `CLOUD_F`) that share the fixed bits `0x9000_X01A`; the variable
/// nibble lives at bits 12-15. Match by masking that nibble off and
/// comparing to the base value `0x9000_001A`.
pub fn is_cloud_tag(tag: u32) -> bool {
    (tag & 0xFFFF_0FFF) == 0x9000_001A
}

/// Read just the reparse tag without pulling the full buffer.
/// Used by the walker when it only needs to classify a reparse host
/// (e.g., "is this a junction so I should skip recursion?") without
/// the 16 KB body allocation.
pub fn read_tag(path: &Path) -> io::Result<u32> {
    let w = wide(path);
    // SAFETY: NUL-terminated wide buffer; handle is RAII-closed.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            0, // metadata-only; FileAttributeTagInfo needs no access bits
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::CreateFileW({}) for read_tag: {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let guard = HandleGuard(h);
    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { mem::zeroed() };
    // SAFETY: `info` is a properly-sized POD struct; the handle is
    // valid (just opened).
    let ok = unsafe {
        GetFileInformationByHandleEx(
            guard.0,
            FileAttributeTagInfo,
            ptr::from_mut::<FILE_ATTRIBUTE_TAG_INFO>(&mut info).cast(),
            u32::try_from(mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>())
                .unwrap_or(u32::MAX),
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::GetFileInformationByHandleEx({}): {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(info.ReparseTag)
}

/// Capture the full reparse-data buffer.
///
/// Returns `Ok((tag, body))` where `body` is the
/// `REPARSE_DATA_BUFFER` body — the bytes that follow the 8-byte
/// fixed header (`ReparseTag` + `ReparseDataLength` + `Reserved`).
/// Restoration via [`apply`] reconstructs the full buffer from
/// `(tag, body)` and the implicit `body.len()`.
///
/// Allocates a single 16 KB buffer (`MAXIMUM_REPARSE_DATA_BUFFER_SIZE`)
/// — the OS-imposed cap on reparse-buffer size. No probe-and-grow
/// loop is needed because the buffer is unconditionally sufficient
/// for any well-formed reparse point.
pub fn capture(path: &Path) -> io::Result<(u32, Vec<u8>)> {
    let w = wide(path);
    // SAFETY: NUL-terminated wide buffer; handle is RAII-closed.
    // Access mask 0 is sufficient for FSCTL_GET_REPARSE_POINT per
    // MSDN — the IOCTL reads metadata only, and the
    // FILE_FLAG_OPEN_REPARSE_POINT flag is what unlocks the call.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::CreateFileW({}) for capture: {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let guard = HandleGuard(h);

    let cap = MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize;
    let mut buf: Vec<u8> = vec![0u8; cap];
    let mut bytes_returned: u32 = 0;
    // SAFETY: `buf` is a heap-owned `Vec` of `cap` bytes; the IOCTL
    // writes the REPARSE_DATA_BUFFER into it. `bytes_returned`
    // receives the actual length.
    let ok = unsafe {
        DeviceIoControl(
            guard.0,
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            cap as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::DeviceIoControl(GET_REPARSE_POINT, {}): {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let n = bytes_returned as usize;
    if n < REPARSE_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "win_reparse::capture({}): truncated buffer ({} < {})",
                path.display(),
                n,
                REPARSE_HEADER_SIZE
            ),
        ));
    }
    // ReparseTag is the first 4 LE bytes.
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let body = buf[REPARSE_HEADER_SIZE..n].to_vec();
    Ok((tag, body))
}

/// Stamp `tag + body` onto `path`. The file or directory must
/// already exist (callers create it via the normal restore-side
/// `create_file` / `create_dir` path; this just adds the reparse
/// metadata layer).
///
/// Refuses third-party tags (M-bit = bit 31 clear) — they require
/// `REPARSE_GUID_DATA_BUFFER` which carries an extra 16-byte GUID
/// not in our wire format. Returns
/// `io::Error(InvalidInput, "third-party tag")`.
pub fn apply(path: &Path, tag: u32, body: &[u8]) -> io::Result<()> {
    if tag & 0x8000_0000 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "win_reparse::apply({}): third-party tag {:#010x} (M-bit clear) — \
                 requires REPARSE_GUID_DATA_BUFFER which we don't carry",
                path.display(),
                tag
            ),
        ));
    }
    let full_len = REPARSE_HEADER_SIZE + body.len();
    if full_len > MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "win_reparse::apply({}): buffer too large ({} > {})",
                path.display(),
                full_len,
                MAXIMUM_REPARSE_DATA_BUFFER_SIZE
            ),
        ));
    }
    let body_len_u16 = u16::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "win_reparse::apply({}): body length {} overflows u16",
                path.display(),
                body.len()
            ),
        )
    })?;

    // Rebuild the full REPARSE_DATA_BUFFER on the stack-equivalent
    // heap (16 KB cap, no oversized payload reaches here per the
    // check above).
    let mut full: Vec<u8> = Vec::with_capacity(full_len);
    full.extend_from_slice(&tag.to_le_bytes()); // ReparseTag
    full.extend_from_slice(&body_len_u16.to_le_bytes()); // ReparseDataLength
    full.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    full.extend_from_slice(body);
    debug_assert_eq!(full.len(), full_len);

    let w = wide(path);
    // SAFETY: NUL-terminated wide buffer; handle is RAII-closed.
    // FILE_WRITE_ATTRIBUTES + FILE_WRITE_EA is the minimum the
    // IOCTL accepts; FILE_FLAG_OPEN_REPARSE_POINT lets us open the
    // host's reparse stream rather than following the link.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::CreateFileW({}) for apply: {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let guard = HandleGuard(h);
    let mut bytes_returned: u32 = 0;
    // SAFETY: `full` is a heap-owned buffer of `full_len` bytes;
    // FSCTL_SET_REPARSE_POINT reads it and writes nothing back.
    let ok = unsafe {
        DeviceIoControl(
            guard.0,
            FSCTL_SET_REPARSE_POINT,
            full.as_ptr().cast::<core::ffi::c_void>() as *mut _,
            full_len as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_reparse::DeviceIoControl(SET_REPARSE_POINT, {}, tag={:#010x}): {:?}",
                path.display(),
                tag,
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

/// RAII guard that closes the wrapped `HANDLE` on drop.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` was obtained from `CreateFileW` and
            // is owned by this guard.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Stamp a junction `link -> target` via `cmd /c mklink /J`.
    /// Both paths must already exist on disk (target as a directory,
    /// link's parent directory as well — link itself must NOT
    /// exist). Returns `true` if mklink succeeded.
    fn stamp_junction(link: &Path, target: &Path) -> bool {
        let status = Command::new("cmd")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status();
        matches!(status, Ok(s) if s.success())
    }

    #[test]
    fn is_reparse_point_returns_false_for_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("plain.txt");
        std::fs::write(&p, b"hello").unwrap();
        assert!(!is_reparse_point(&p).unwrap());
    }

    #[test]
    fn is_reparse_point_returns_true_for_a_junction() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        if !stamp_junction(&link, &target) {
            eprintln!("skipping: mklink /J not available in this env");
            return;
        }
        assert!(is_reparse_point(&link).unwrap());
    }

    #[test]
    fn read_tag_returns_mount_point_for_a_junction() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        if !stamp_junction(&link, &target) {
            eprintln!("skipping: mklink /J not available in this env");
            return;
        }
        let tag = read_tag(&link).unwrap();
        assert_eq!(
            tag, IO_REPARSE_TAG_MOUNT_POINT,
            "expected MOUNT_POINT, got {tag:#010x}"
        );
    }

    #[test]
    fn is_cloud_tag_matches_the_family() {
        // Base CLOUD tag.
        assert!(is_cloud_tag(0x9000_001A));
        // All 16 instance variants share the masked-equality.
        for instance in 0u32..16 {
            let t = 0x9000_001A | (instance << 12);
            assert!(is_cloud_tag(t), "expected cloud, got {t:#010x}");
        }
        // Adjacent Microsoft tags are NOT cloud.
        assert!(!is_cloud_tag(IO_REPARSE_TAG_MOUNT_POINT));
        assert!(!is_cloud_tag(IO_REPARSE_TAG_SYMLINK));
        assert!(!is_cloud_tag(0x8000_0017)); // WOF
        assert!(!is_cloud_tag(0x9000_0019)); // GLOBAL_REPARSE (close but no)
        assert!(!is_cloud_tag(0x9000_001B)); // adjacent
    }

    /// Capture a junction's reparse blob, then apply it to a fresh
    /// empty dir; the result must read back byte-identical.
    /// Validates the round-trip pipe end to end.
    #[test]
    fn capture_then_apply_round_trips_a_junction() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let src_link = dir.path().join("src_link");
        if !stamp_junction(&src_link, &target) {
            eprintln!("skipping: mklink /J not available in this env");
            return;
        }
        let (tag, body) = capture(&src_link).unwrap();
        assert_eq!(tag, IO_REPARSE_TAG_MOUNT_POINT);
        assert!(!body.is_empty());

        // Apply onto a fresh empty directory.
        let dst_link = dir.path().join("dst_link");
        std::fs::create_dir(&dst_link).unwrap();
        apply(&dst_link, tag, &body).expect("apply must succeed on an empty dir");

        // Re-capture and demand byte-identity.
        let (got_tag, got_body) = capture(&dst_link).unwrap();
        assert_eq!(got_tag, tag);
        assert_eq!(got_body, body);
    }

    /// `apply` refuses third-party tags (M-bit = 0).
    #[test]
    fn apply_refuses_third_party_tags() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("victim");
        std::fs::create_dir(&p).unwrap();
        let err = apply(&p, 0x0000_1234, &[0u8; 4]).expect_err("should refuse M=0");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
