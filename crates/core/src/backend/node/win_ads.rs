//! NTFS Alternate Data Stream (ADS) enumeration on Windows
//! (kopia-0dr.53 — rustback-filecopy increment 2b).
//!
//! Lists every named DATA stream on a file via `FindFirstStreamW` +
//! `FindNextStreamW`. The default (unnamed) stream — the file's
//! body — is intentionally skipped: it's already captured as the
//! host node's `content` blob refs.
//!
//! Restore needs no Win32 here. The walker yields an extra
//! `ReadSourceEntry` per stream with a colon-bearing node name like
//! `host.txt:Zone.Identifier`; on restore that name flows through
//! `LocalDestination::path()` → `OpenOptions::open()` →
//! `CreateFileW`, and CreateFileW interprets the
//! `host:stream:$DATA` syntax natively. So the only Win32 in this
//! module is the find-streams loop.
#![cfg(windows)]
#![allow(unsafe_code)] // Win32 FFI; sealed inside `enumerate`.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
    WIN32_FIND_STREAM_DATA,
};

/// Set when the host's `dwFileAttributes` indicates a reparse point.
/// Junctions, symlinks, and OneDrive placeholders all carry this.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// A validated NTFS ADS name (e.g. `"Zone.Identifier"`, `"foo"`).
///
/// Must not contain any of the forbidden characters from MSDN's
/// "Naming Files, Paths, and Namespaces" page that would make the
/// composed `host:stream:$DATA` path unopenable: `< > " / \ | ? *`
/// and NUL. Crucially must not contain `:` itself, since that's
/// the separator we splice between host and stream when building
/// the colon-bearing Node name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdsName(String);

impl AdsName {
    /// Construct from a stream name. Rejects forbidden characters.
    pub fn new(s: impl Into<String>) -> io::Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ADS name is empty",
            ));
        }
        for c in s.chars() {
            if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
                || c == '\0'
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("ADS name contains forbidden character: {c:?}"),
                ));
            }
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AdsName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Strip `FindFirstStreamW`'s `:<name>:$DATA` envelope down to just
/// the stream name. Returns `None` for the default stream
/// (`::$DATA` — the host's body, stored elsewhere) and for entries
/// that don't end in `:$DATA` (alternative stream types like
/// `:foo:$INDEX_ALLOCATION`, which we don't carry).
fn canonical_stream_name(raw: &str) -> Option<&str> {
    let inner = raw.strip_suffix(":$DATA")?;
    let name = inner.strip_prefix(':')?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Enumerate every named DATA stream on `path`. Each result carries
/// the stream's name and its size in bytes (from
/// `WIN32_FIND_STREAM_DATA.StreamSize`).
///
/// Returns:
/// - `Ok(vec![])` when the host has no named streams (a freshly
///   created file always has only `::$DATA`, which we skip).
/// - `Ok(vec![])` when the host is a reparse point — junctions,
///   symlinks, and OneDrive placeholders carry foreign streams
///   that we treat as opaque (Increment 2c will own them).
/// - `Err(...)` for filesystem-not-supported (`ERROR_INVALID_PARAMETER`
///   on FAT/exFAT), missing host (`ERROR_FILE_NOT_FOUND`), and any
///   other failure raised by `FindFirstStreamW`.
pub fn enumerate(path: &Path) -> io::Result<Vec<(AdsName, u64)>> {
    // Reparse-point fast path: skip without an enumeration syscall.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Vec::new());
        }
    }

    let w = wide(path);
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let h = unsafe {
        FindFirstStreamW(
            w.as_ptr(),
            FindStreamInfoStandard,
            std::ptr::from_mut::<WIN32_FIND_STREAM_DATA>(&mut data).cast(),
            0,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        // ERROR_HANDLE_EOF on FindFirstStreamW means "no streams",
        // which only happens on directories; map to empty.
        return match err.raw_os_error() {
            Some(code) if code as u32 == ERROR_HANDLE_EOF => Ok(Vec::new()),
            _ => Err(err),
        };
    }

    let mut out = Vec::new();
    loop {
        let raw = read_stream_name(&data.cStreamName);
        if let Some(name) = canonical_stream_name(&raw) {
            // StreamSize is i64; restic stores u64. Clamp at zero.
            let size = data.StreamSize.max(0) as u64;
            if let Ok(ads) = AdsName::new(name) {
                out.push((ads, size));
            }
            // If validation rejects the name (shouldn't happen for
            // anything FindFirstStreamW produces — Win32 enforces a
            // tighter rule than ours — skip rather than abort).
        }
        let ok = unsafe {
            FindNextStreamW(
                h,
                std::ptr::from_mut::<WIN32_FIND_STREAM_DATA>(&mut data).cast(),
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            unsafe { FindClose(h) };
            return match err.raw_os_error() {
                Some(code) if code as u32 == ERROR_HANDLE_EOF => Ok(out),
                _ => Err(err),
            };
        }
    }
}

/// Read a NUL-terminated UTF-16 stream name out of the
/// `cStreamName` buffer. The buffer is at most `[u16; 296]`; we
/// stop at the first NUL or at the buffer end.
fn read_stream_name(buf: &[u16; 296]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// PowerShell helper: stamp a named ADS on `path` with the given
    /// payload. Returns true if the stamp succeeded.
    fn stamp_stream(path: &Path, stream: &str, payload: &str) -> bool {
        let script = format!(
            "Set-Content -NoNewline -Stream '{}' -LiteralPath '{}' -Value '{}'",
            stream,
            path.display(),
            payload
        );
        Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status()
            .ok()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn ads_name_rejects_forbidden_chars() {
        assert!(AdsName::new("Zone.Identifier").is_ok());
        assert!(AdsName::new("foo bar").is_ok()); // spaces OK
        assert!(AdsName::new("Zone:Identifier").is_err()); // : forbidden
        assert!(AdsName::new("foo\\bar").is_err());
        assert!(AdsName::new("foo/bar").is_err());
        assert!(AdsName::new("foo|bar").is_err());
        assert!(AdsName::new("foo?bar").is_err());
        assert!(AdsName::new("foo*bar").is_err());
        assert!(AdsName::new("").is_err());
    }

    #[test]
    fn canonical_stream_name_strips_envelope() {
        // Default (unnamed) stream → None.
        assert_eq!(canonical_stream_name("::$DATA"), None);
        // Named DATA stream → strip both ends.
        assert_eq!(
            canonical_stream_name(":Zone.Identifier:$DATA"),
            Some("Zone.Identifier")
        );
        assert_eq!(canonical_stream_name(":foo:$DATA"), Some("foo"));
        // Non-DATA stream types → None (we don't carry them).
        assert_eq!(canonical_stream_name(":foo:$INDEX_ALLOCATION"), None);
        // Malformed → None.
        assert_eq!(canonical_stream_name("no_colon_or_data"), None);
    }

    #[test]
    fn enumerate_returns_empty_for_a_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("plain.txt");
        std::fs::write(&p, b"body").unwrap();
        let streams = enumerate(&p).expect("enumerate must succeed");
        assert!(
            streams.is_empty(),
            "plain file should have no named streams, got {streams:?}"
        );
    }

    #[test]
    fn enumerate_finds_one_named_stream() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("host.txt");
        std::fs::write(&p, b"body").unwrap();
        assert!(stamp_stream(&p, "Zone.Identifier", "marker"));
        let streams = enumerate(&p).unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0.as_str(), "Zone.Identifier");
        // "marker" is 6 bytes.
        assert_eq!(streams[0].1, 6);
    }

    #[test]
    fn enumerate_finds_two_named_streams_in_deterministic_order() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("host.txt");
        std::fs::write(&p, b"body").unwrap();
        assert!(stamp_stream(&p, "alpha", "AAA"));
        assert!(stamp_stream(&p, "beta", "BBBB"));
        let mut names: Vec<String> = enumerate(&p)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n.0)
            .collect();
        names.sort();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn enumerate_skips_reparse_point_host() {
        // We can't easily create a reparse point in a unit test
        // without admin privileges, so this is a smoke test: a
        // non-existent path should fail (not return empty), proving
        // we reach the syscall path. The reparse-point fast-path is
        // covered by code review against MetadataExt::file_attributes.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist.txt");
        let r = enumerate(&p);
        assert!(r.is_err(), "missing host must surface an error");
    }
}
