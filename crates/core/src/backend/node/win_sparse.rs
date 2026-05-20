//! NTFS sparse-file capture + restore (kopia-0dr.54 —
//! rustback-filecopy increment 2d).
//!
//! NTFS sparse files have address ranges marked as unallocated
//! "holes" that read back as zeros but consume no disk space. This
//! module provides three primitives:
//!
//! 1. [`is_sparse_file`] — query `FILE_ATTRIBUTE_SPARSE_FILE` via
//!    `GetFileAttributesExW`. Same syscall the 2b
//!    `windows.file_attributes` capture already pays for; exposed
//!    here as a convenience predicate.
//! 2. [`enumerate_allocated_ranges`] — list every allocated extent
//!    on a sparse file via `FSCTL_QUERY_ALLOCATED_RANGES`. The
//!    capture-side wiring stores these in
//!    `Metadata.generic_attributes["windows.sparse_extents"]`.
//! 3. [`apply_sparseness`] — flag the destination sparse via
//!    `FSCTL_SET_SPARSE` and punch holes for every range NOT in
//!    the source's allocated extents via `FSCTL_SET_ZERO_DATA`.
//!    Called post-write from `LocalDestination::set_generic_attributes`.
//!
//! Ported from `rustback/src/mirror/sparse.rs` (the block-tier
//! mirror worker's sparse preflight, closed bead kopia-dyj), with
//! the additional apply helper.
//!
//! All three are best-effort: failures bubble as `io::Error`, and
//! the calling code logs and continues rather than aborting.

#![cfg(windows)]
#![allow(unsafe_code)] // Win32 FFI; sealed inside this module.

use std::io;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_MORE_DATA, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesExW, GetFileExInfoStandard, FILE_ATTRIBUTE_SPARSE_FILE,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WIN32_FILE_ATTRIBUTE_DATA,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_ALLOCATED_RANGE_BUFFER, FILE_ZERO_DATA_INFORMATION, FSCTL_QUERY_ALLOCATED_RANGES,
    FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Returns `true` if `path` is flagged sparse (the NTFS
/// `FILE_ATTRIBUTE_SPARSE_FILE` bit is set).
pub fn is_sparse_file(path: &Path) -> io::Result<bool> {
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
        Ok(data.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE != 0)
    }
}

/// Enumerate the allocated (non-hole) byte ranges of a sparse file.
///
/// Returns `Ok(vec![])` when the file has no allocated content
/// (fully sparse). For a non-sparse file NTFS would return one
/// range covering `[0, size)` — call [`is_sparse_file`] first if
/// you want to short-circuit non-sparse files.
///
/// `(offset, length)` pairs are sorted by offset and coalesced
/// (defensive: NTFS already returns them sorted, but a multi-call
/// sequence on a fragmented file could split contiguous extents
/// across calls).
pub fn enumerate_allocated_ranges(path: &Path) -> io::Result<Vec<(i64, i64)>> {
    // Open with `FILE_FLAG_BACKUP_SEMANTICS` so we can also work
    // on sparse directories (rare but possible). Read-only is
    // sufficient for the IOCTL.
    let w = wide(path);
    // SAFETY: NUL-terminated wide buffer; HANDLE wrapped in a
    // close-on-drop guard below.
    // Look up the file size first — DeviceIoControl needs an
    // upper bound on the query range. Doing this before
    // CreateFileW also avoids holding a handle while we touch the
    // path twice.
    let file_size = std::fs::metadata(path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("win_sparse::metadata({}): {e}", path.display()),
            )
        })?
        .len() as i64;

    // GENERIC_READ is the canonical access bracket for
    // FSCTL_QUERY_ALLOCATED_RANGES per MSDN's "Using the FSCTL"
    // sample. FILE_READ_ATTRIBUTES alone is enough in theory but
    // some Windows builds reject the IOCTL without read-data
    // access on the handle.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "win_sparse::CreateFileW({}) {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    let guard = HandleGuard(h);

    let mut out_buf: Vec<FILE_ALLOCATED_RANGE_BUFFER> =
        vec![unsafe { mem::zeroed() }; 256];
    let mut ranges: Vec<(i64, i64)> = Vec::new();
    let mut next_offset: i64 = 0;

    loop {
        if next_offset >= file_size {
            break;
        }
        let mut iter_query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: next_offset,
            Length: file_size - next_offset,
        };
        let mut bytes_returned: u32 = 0;
        // SAFETY: `iter_query` is a properly-aligned input struct;
        // `out_buf` is a heap-owned `Vec` with capacity for the
        // requested length.
        let ok = unsafe {
            DeviceIoControl(
                guard.0,
                FSCTL_QUERY_ALLOCATED_RANGES,
                ptr::from_mut::<FILE_ALLOCATED_RANGE_BUFFER>(&mut iter_query).cast(),
                u32::try_from(mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>())
                    .unwrap_or(u32::MAX),
                out_buf.as_mut_ptr().cast(),
                u32::try_from(out_buf.len() * mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>())
                    .unwrap_or(u32::MAX),
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        // ok != 0 → full success; ok == 0 with ERROR_MORE_DATA →
        // partial result, advance and loop.
        let last_err = if ok == 0 {
            // SAFETY: GetLastError() is always callable.
            unsafe { GetLastError() }
        } else {
            0
        };
        if ok == 0 && last_err != ERROR_MORE_DATA {
            return Err(io::Error::new(
                io::Error::from_raw_os_error(last_err as i32).kind(),
                format!(
                    "win_sparse::DeviceIoControl(QUERY_ALLOCATED_RANGES) GLE={last_err}"
                ),
            ));
        }

        let n = bytes_returned as usize / mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if n == 0 {
            break;
        }
        for r in out_buf.iter().take(n) {
            ranges.push((r.FileOffset, r.Length));
        }
        let last = out_buf[n - 1];
        next_offset = last.FileOffset + last.Length;

        if ok != 0 {
            break;
        }
    }

    // Coalesce adjacent extents (defensive).
    ranges.sort_by_key(|r| r.0);
    let mut coalesced: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
    for (off, len) in ranges {
        if let Some(last) = coalesced.last_mut() {
            if last.0 + last.1 == off {
                last.1 += len;
                continue;
            }
        }
        coalesced.push((off, len));
    }

    Ok(coalesced)
}

/// Flag a destination file sparse and punch the holes implied by
/// `allocated_extents` (the source's allocated ranges, from
/// [`enumerate_allocated_ranges`]). The complement within
/// `[0, total_size)` is treated as holes and deallocated via
/// `FSCTL_SET_ZERO_DATA`.
///
/// `allocated_extents` must be `[i64; 2]` pairs in the
/// `[FileOffset, Length]` shape used by the wire-format
/// `windows.sparse_extents` key (matching `FILE_ALLOCATED_RANGE_BUFFER`).
///
/// Idempotent: calling on an already-sparse file with the same
/// extents is a no-op. Best-effort: a non-NTFS target (FAT/exFAT)
/// returns `ERROR_INVALID_FUNCTION`; the caller logs and
/// continues, leaving the file as a dense restore.
pub fn apply_sparseness(
    path: &Path,
    allocated_extents: &[[i64; 2]],
    total_size: u64,
) -> io::Result<()> {
    let w = wide(path);
    // SAFETY: NUL-terminated wide buffer; HANDLE wrapped in
    // close-on-drop guard.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let guard = HandleGuard(h);

    // Step 1: FSCTL_SET_SPARSE flags the file. Pass null input —
    // the IOCTL has no parameters in the standard case.
    let mut bytes_returned: u32 = 0;
    // SAFETY: HANDLE held by guard; null input/output buffers are
    // explicitly permitted by FSCTL_SET_SPARSE.
    let ok = unsafe {
        DeviceIoControl(
            guard.0,
            FSCTL_SET_SPARSE,
            ptr::null(),
            0,
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
                "win_sparse::FSCTL_SET_SPARSE({}) {:?}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }

    // Step 2: punch each hole in the complement of
    // `allocated_extents` within `[0, total_size)`. The complement
    // is computed inline so we don't need to copy + sort the input.
    let total = total_size as i64;
    let mut cursor: i64 = 0;
    // Defensive: ensure the extents are sorted before complementing.
    // Most callers will already pass them sorted (from
    // enumerate_allocated_ranges), but accept any order.
    let mut sorted: Vec<[i64; 2]> = allocated_extents.to_vec();
    sorted.sort_by_key(|r| r[0]);

    for [off, len] in sorted {
        if off > cursor {
            // Hole at [cursor, off)
            punch_hole(guard.0, cursor, off)?;
        }
        cursor = (off + len).max(cursor);
    }
    if cursor < total {
        // Trailing hole at [cursor, total)
        punch_hole(guard.0, cursor, total)?;
    }
    Ok(())
}

/// Inner helper for [`apply_sparseness`]: invoke `FSCTL_SET_ZERO_DATA`
/// to deallocate a single half-open range `[start, end)` on the
/// already-sparse file. Caller must have already called
/// `FSCTL_SET_SPARSE` on the handle (otherwise NTFS still zeros the
/// range but does not deallocate it).
fn punch_hole(h: HANDLE, start: i64, end: i64) -> io::Result<()> {
    if end <= start {
        return Ok(());
    }
    let mut zero = FILE_ZERO_DATA_INFORMATION {
        FileOffset: start,
        BeyondFinalZero: end,
    };
    let mut bytes_returned: u32 = 0;
    // SAFETY: stack-allocated POD input; null output buffer; valid
    // handle.
    let ok = unsafe {
        DeviceIoControl(
            h,
            FSCTL_SET_ZERO_DATA,
            ptr::from_mut::<FILE_ZERO_DATA_INFORMATION>(&mut zero).cast(),
            u32::try_from(mem::size_of::<FILE_ZERO_DATA_INFORMATION>())
                .unwrap_or(u32::MAX),
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
                "win_sparse::FSCTL_SET_ZERO_DATA([{start},{end})) {:?}",
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

    /// Stamp the sparse flag on a path via `fsutil sparse setflag`.
    /// Returns true on success.
    fn stamp_sparse_flag(path: &Path) -> bool {
        Command::new("fsutil")
            .args(["sparse", "setflag", &path.display().to_string()])
            .status()
            .ok()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Mark `[offset, offset+length)` as a deallocated hole via
    /// `fsutil sparse setrange`. Returns true on success.
    fn stamp_hole(path: &Path, offset: u64, length: u64) -> bool {
        Command::new("fsutil")
            .args([
                "sparse",
                "setrange",
                &path.display().to_string(),
                &offset.to_string(),
                &length.to_string(),
            ])
            .status()
            .ok()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn is_sparse_file_distinguishes_flagged_from_plain() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.bin");
        std::fs::write(&plain, vec![0u8; 1024]).unwrap();
        assert!(!is_sparse_file(&plain).unwrap(), "plain file is not sparse");

        let sparse = dir.path().join("sparse.bin");
        std::fs::write(&sparse, vec![0u8; 1024]).unwrap();
        assert!(stamp_sparse_flag(&sparse), "fsutil setflag must succeed");
        assert!(
            is_sparse_file(&sparse).unwrap(),
            "stamped file must be sparse"
        );
    }

    #[test]
    fn enumerate_allocated_ranges_finds_punched_holes() {
        // NTFS sparse-file deallocation has a 64 KB minimum
        // granularity (the file system rounds zero-data ranges
        // smaller than this up to the nearest 64 KB cluster-group).
        // Smaller "holes" just zero the bytes without freeing
        // space, which would make this test look like it failed
        // even though the IOCTL succeeded. Use a 1 MB fixture with
        // a 256 KB hole to stay well above the granularity floor.
        const FILE_SIZE: u64 = 1024 * 1024;
        const HOLE_START: u64 = 256 * 1024;
        const HOLE_LEN: u64 = 256 * 1024;

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("hole.bin");
        std::fs::write(&p, vec![0xAA; FILE_SIZE as usize]).unwrap();
        assert!(stamp_sparse_flag(&p), "fsutil setflag must succeed");
        assert!(
            stamp_hole(&p, HOLE_START, HOLE_LEN),
            "fsutil setrange must succeed"
        );

        let ranges = enumerate_allocated_ranges(&p).unwrap();
        assert!(!ranges.is_empty(), "must have at least one allocated extent");
        let hole_end = HOLE_START + HOLE_LEN;
        for &(off, len) in &ranges {
            let end = (off + len) as u64;
            assert!(
                end <= HOLE_START || (off as u64) >= hole_end,
                "extent [{off},{end}) overlaps the punched hole \
                 [{HOLE_START},{hole_end})"
            );
        }
    }

    #[test]
    fn enumerate_returns_empty_for_a_zero_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty.bin");
        std::fs::write(&p, b"").unwrap();
        let ranges = enumerate_allocated_ranges(&p).unwrap();
        assert!(ranges.is_empty(), "zero-byte file has no allocated ranges");
    }

    #[test]
    fn apply_sparseness_round_trips_a_known_extent_layout() {
        // 1 MB fixture (NTFS sparse minimum hole granularity is
        // 64 KB; smaller "holes" don't deallocate). Declare
        // allocated only at [0, 64 KB) + [512 KB, 64 KB).
        // Expect punches at [64 KB, 512 KB) and [576 KB, 1 MB).
        const FILE_SIZE: u64 = 1024 * 1024;

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rt.bin");
        std::fs::write(&p, vec![0xAA; FILE_SIZE as usize]).unwrap();

        apply_sparseness(
            &p,
            &[[0, 65536], [524288, 65536]],
            FILE_SIZE,
        )
        .unwrap();

        assert!(is_sparse_file(&p).unwrap(), "file must be sparse after apply");
        let ranges = enumerate_allocated_ranges(&p).unwrap();
        // Allocated extents must all lie inside one of the two
        // declared regions (NTFS may shrink them slightly to
        // cluster-aligned subsets, but never grow them).
        for &(off, len) in &ranges {
            let end = off + len;
            let fits_in_first = off >= 0 && end <= 65536;
            let fits_in_second = off >= 524288 && end <= 524288 + 65536;
            assert!(
                fits_in_first || fits_in_second,
                "unexpected allocated extent [{off},{end}) after apply_sparseness; \
                 declared allocated = [0,64KB) + [512KB,64KB)"
            );
        }
        // And: SOMETHING must be deallocated — we should not see
        // the whole file as one giant allocated extent.
        let one_giant_extent = ranges.len() == 1
            && ranges[0] == (0i64, FILE_SIZE as i64);
        assert!(
            !one_giant_extent,
            "apply_sparseness produced no holes; ranges = {ranges:?}"
        );
    }
}
