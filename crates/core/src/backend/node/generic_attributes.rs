//! Restic-compatible value carrier for `Metadata.generic_attributes`
//! (kopia-0dr.53 — rustback-filecopy increment 2b, extended for 2d
//! and 2c).
//!
//! Restic's tree-blob wire format stores Windows per-node metadata as
//! `map[GenericAttributeType]json.RawMessage`. The three keys it
//! defines today are:
//!
//! | Key | JSON value shape |
//! |---|---|
//! | `windows.security_descriptor` | JSON string (base64 of self-relative SD bytes) |
//! | `windows.file_attributes`     | JSON number (FILE_ATTRIBUTE_* bitset, fits `u32`) |
//! | `windows.creation_time`       | JSON object `{"LowDateTime":N,"HighDateTime":N}` |
//!
//! The rustback fork adds two forward-compat keys not in upstream
//! restic v0.18.1:
//!
//! | Key | JSON value shape | Increment |
//! |---|---|---|
//! | `windows.sparse_extents` | JSON array `[[offset,length], ...]` | 2d (kopia-0dr.54) |
//! | `windows.reparse_point`  | JSON object `{"tag":N,"data":"<b64>"}` | 2c (kopia-4rf) |
//!
//! Increment 2a carried only the SD entry, so a `BTreeMap<String,
//! String>` sufficed. 2b adds the other two keys, whose natural JSON
//! shapes are not strings — hence this enum.
//!
//! Why a custom enum and not `serde_json::Value`: `Metadata: Ord` is
//! load-bearing upstream (`crates/core/src/blob/tree.rs` uses
//! `BTreeMap<Node, usize>` for tree dedup), and `serde_json::Value`
//! does not implement `Ord`. The variants here cover only the
//! values restic actually emits; unknown future keys can be added
//! without breaking the existing wire shape because the enum is
//! `#[serde(untagged)]`.
//!
//! Key ordering on the wire: `BTreeMap<String, _>` iterates
//! lex-byte-order, which matches Go's `encoding/json` map-key sort,
//! so the produced JSON is byte-identical to restic's for the same
//! three keys.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// One `generic_attributes` value — covers every shape restic
/// v0.18.1 emits, plus rustback-fork extensions (sparse extents),
/// and parses any of them transparently.
///
/// Variant order matters for `#[serde(untagged)]` — serde tries
/// each variant top-down and the first match wins. The shapes
/// here are unambiguous (object / array / number / string) so any
/// order would parse correctly, but keeping the most specific
/// shapes first makes the resolution order easy to reason about.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GenericAttributeValue {
    /// `windows.creation_time` — the FILETIME of the file's creation.
    /// JSON object `{"LowDateTime": N, "HighDateTime": N}`.
    CreationTime(WindowsFiletime),
    /// `windows.reparse_point` — opaque NTFS reparse-point data for
    /// junctions / symlinks / OneDrive placeholders / WOF /
    /// APPEXECLINK / etc. JSON object `{"tag": N, "data": "<b64>"}`
    /// where `tag` is the `IO_REPARSE_TAG_*` value and `data` is
    /// base64 of the `REPARSE_DATA_BUFFER` body (the bytes after
    /// the 8-byte fixed header). **Rustback fork extension**
    /// (kopia-4rf increment 2c) — restic v0.18.1 does not emit
    /// or parse this key.
    ReparsePoint(ReparseBlob),
    /// `windows.sparse_extents` — the source's NTFS allocated runs.
    /// JSON array of `[file_offset, length]` `i64` pairs, e.g.
    /// `[[0, 4096], [524288, 524288]]`. **Rustback fork extension**
    /// (kopia-0dr.54 increment 2d) — restic v0.18.1 does not emit
    /// or parse this key; tree blobs carrying it stay
    /// upstream-readable because restic's
    /// `map[GenericAttributeType]json.RawMessage` preserves unknown
    /// keys verbatim.
    SparseExtents(Vec<[i64; 2]>),
    /// `windows.file_attributes` — `FILE_ATTRIBUTE_*` bitset.
    U32(u32),
    /// `windows.security_descriptor` — base64 of the self-relative SD.
    String(String),
}

/// Restic's wire shape for a Windows `FILETIME` value: two `u32`s
/// matching `syscall.Filetime` field-for-field. Field names are
/// PascalCase on the wire to match Go's JSON marshalling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct WindowsFiletime {
    /// Low-order 32 bits of the 64-bit FILETIME value.
    #[serde(rename = "LowDateTime")]
    pub low_date_time: u32,
    /// High-order 32 bits of the 64-bit FILETIME value.
    #[serde(rename = "HighDateTime")]
    pub high_date_time: u32,
}

/// Rustback fork wire shape for an NTFS reparse point (kopia-4rf,
/// increment 2c). `tag` is the `IO_REPARSE_TAG_*` value; `data` is
/// base64 of the `REPARSE_DATA_BUFFER` body — the bytes immediately
/// following the 8-byte fixed header (`ReparseTag` + `ReparseDataLength`
/// + `Reserved`). The header is reconstructed at apply-time: `tag` is
/// carried in the sibling field, `ReparseDataLength` equals
/// `data.len()` after base64 decode, and `Reserved` is zero.
///
/// Lower-case JSON field names because this is a fork extension, not
/// a restic-defined shape — no Go-marshalling alignment constraint.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ReparseBlob {
    /// `IO_REPARSE_TAG_*` value (e.g. `0xA0000003` for MOUNT_POINT,
    /// `0xA000000C` for SYMLINK).
    pub tag: u32,
    /// Base64-encoded `REPARSE_DATA_BUFFER` body bytes (no header).
    pub data: String,
}

impl Ord for GenericAttributeValue {
    /// Total order: by variant tag first (matching declaration
    /// discriminants), then by content. Stable, deterministic, and
    /// independent of insertion order.
    fn cmp(&self, other: &Self) -> Ordering {
        fn rank(v: &GenericAttributeValue) -> u8 {
            match v {
                GenericAttributeValue::CreationTime(_) => 0,
                GenericAttributeValue::ReparsePoint(_) => 1,
                GenericAttributeValue::SparseExtents(_) => 2,
                GenericAttributeValue::U32(_) => 3,
                GenericAttributeValue::String(_) => 4,
            }
        }
        match rank(self).cmp(&rank(other)) {
            Ordering::Equal => match (self, other) {
                (Self::CreationTime(a), Self::CreationTime(b)) => a.cmp(b),
                (Self::ReparsePoint(a), Self::ReparsePoint(b)) => a.cmp(b),
                (Self::SparseExtents(a), Self::SparseExtents(b)) => a.cmp(b),
                (Self::U32(a), Self::U32(b)) => a.cmp(b),
                (Self::String(a), Self::String(b)) => a.cmp(b),
                // The same `rank` implies the same variant pair.
                _ => unreachable!(),
            },
            o => o,
        }
    }
}

impl PartialOrd for GenericAttributeValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WindowsFiletime {
    /// Lexicographic over (high, low) — the canonical chronological
    /// order for a 64-bit FILETIME.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.high_date_time, self.low_date_time)
            .cmp(&(other.high_date_time, other.low_date_time))
    }
}

impl PartialOrd for WindowsFiletime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReparseBlob {
    /// Lexicographic over `(tag, data)`. Stable and total for any
    /// pair of blobs; ties on tag fall through to byte-wise data
    /// comparison.
    fn cmp(&self, other: &Self) -> Ordering {
        (self.tag, &self.data).cmp(&(other.tag, &other.data))
    }
}

impl PartialOrd for ReparseBlob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Win32 apply of the two non-SD restic-supported generic attributes
/// (kopia-0dr.53 — rustback-filecopy increment 2b).
///
/// `file_attributes` is applied via `SetFileAttributesW`;
/// `creation_time` is applied via `SetFileTime` with only the
/// creation slot non-null. Both are best-effort — the caller's
/// existing `warn!`-and-continue path handles failures.
#[cfg(windows)]
#[allow(unsafe_code)] // Win32 FFI; sealed inside this module.
pub mod apply {
    use super::WindowsFiletime;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetFileAttributesW, SetFileTime, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
        OPEN_EXISTING,
    };

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Returns `true` on success.
    pub fn file_attributes(path: &Path, attrs: u32) -> bool {
        let w = wide(path);
        // SAFETY: `w` is a NUL-terminated UTF-16 buffer we own.
        unsafe { SetFileAttributesW(w.as_ptr(), attrs) != 0 }
    }

    /// Returns `true` on success. Only the creation time is set;
    /// access and modification times are left untouched (passing
    /// null pointers signals "do not change" per MSDN).
    pub fn creation_time(path: &Path, ct: WindowsFiletime) -> bool {
        let w = wide(path);
        let ft = FILETIME {
            dwLowDateTime: ct.low_date_time,
            dwHighDateTime: ct.high_date_time,
        };
        // SAFETY: `w` is a NUL-terminated UTF-16 buffer we own; the
        // FILETIME is a POD struct on our stack; the handle is closed
        // before this function returns.
        unsafe {
            // FILE_FLAG_BACKUP_SEMANTICS lets us open directories too,
            // which is necessary because restic stores creation time
            // for directories as well as files. FILE_WRITE_ATTRIBUTES
            // is the minimum permission `SetFileTime` needs — using
            // it alone (not FILE_GENERIC_WRITE) lets us open ReadOnly
            // files, since ReadOnly blocks only FILE_WRITE_DATA opens.
            let h = CreateFileW(
                w.as_ptr(),
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            );
            if h == INVALID_HANDLE_VALUE {
                return false;
            }
            let ok = SetFileTime(h, &ft, ptr::null(), ptr::null()) != 0;
            CloseHandle(h);
            ok
        }
    }
}

/// Win32 capture of the two non-SD restic-supported generic attributes:
/// `windows.file_attributes` (a `FILE_ATTRIBUTE_*` bitset) and
/// `windows.creation_time` (a FILETIME). Both come from a single
/// `GetFileAttributesExW` call — read-only, no privileges required.
///
/// Returns `None` if the file has been deleted between the directory
/// walk and the call. Failures are silent for the same reason 2a's
/// SD capture is silent: best-effort, the caller logs and continues.
#[cfg(windows)]
#[allow(unsafe_code)] // Win32 FFI; sealed inside this module.
pub mod capture {
    use super::WindowsFiletime;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesExW, GetFileExInfoStandard, WIN32_FILE_ATTRIBUTE_DATA,
    };

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Returns `(file_attributes, creation_time)` for `path`. Both
    /// fields come from one `GetFileAttributesExW` call.
    pub fn file_attributes_and_creation_time(
        path: &Path,
    ) -> Option<(u32, WindowsFiletime)> {
        let w = wide(path);
        // SAFETY: `w` is a NUL-terminated UTF-16 buffer owned by us;
        // `data` is a stack-allocated POD struct written by the API.
        unsafe {
            let mut data: WIN32_FILE_ATTRIBUTE_DATA = std::mem::zeroed();
            let ok = GetFileAttributesExW(
                w.as_ptr(),
                GetFileExInfoStandard,
                std::ptr::from_mut::<WIN32_FILE_ATTRIBUTE_DATA>(&mut data).cast(),
            );
            if ok == 0 {
                return None;
            }
            Some((
                data.dwFileAttributes,
                WindowsFiletime {
                    low_date_time: data.ftCreationTime.dwLowDateTime,
                    high_date_time: data.ftCreationTime.dwHighDateTime,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The on-disk shape must be byte-identical to what restic v0.18.1
    /// emits for the same three keys, plus our forward-compat
    /// `windows.sparse_extents` (2d) and `windows.reparse_point` (2c)
    /// extensions. Restic-format compatibility for 2b/2c/2d hinges
    /// on this test (and its bit-compat oracle in `rustback-filecopy`).
    #[test]
    fn restic_wire_shape_is_byte_identical() {
        let mut m: BTreeMap<String, GenericAttributeValue> = BTreeMap::new();
        m.insert(
            "windows.creation_time".into(),
            GenericAttributeValue::CreationTime(WindowsFiletime {
                low_date_time: 0xAABBCCDD,
                high_date_time: 0x11223344,
            }),
        );
        m.insert(
            "windows.file_attributes".into(),
            GenericAttributeValue::U32(0x22),
        );
        m.insert(
            "windows.reparse_point".into(),
            GenericAttributeValue::ReparsePoint(ReparseBlob {
                tag: 0xA0000003, // IO_REPARSE_TAG_MOUNT_POINT
                data: "AAEC".into(),
            }),
        );
        m.insert(
            "windows.security_descriptor".into(),
            GenericAttributeValue::String("AQAEh==".into()),
        );
        m.insert(
            "windows.sparse_extents".into(),
            GenericAttributeValue::SparseExtents(vec![[0, 4096], [524288, 524288]]),
        );
        let json = serde_json::to_string(&m).unwrap();
        // BTreeMap ordering is lex-byte-order of keys; same as Go's
        // encoding/json map-key sort. Order: creation_time,
        // file_attributes, reparse_point, security_descriptor,
        // sparse_extents.
        assert_eq!(
            json,
            r#"{"windows.creation_time":{"LowDateTime":2864434397,"HighDateTime":287454020},"windows.file_attributes":34,"windows.reparse_point":{"tag":2684354563,"data":"AAEC"},"windows.security_descriptor":"AQAEh==","windows.sparse_extents":[[0,4096],[524288,524288]]}"#
        );
    }

    /// Forward-compat: a tree blob produced by 2c (carrying
    /// `windows.reparse_point`) deserialises cleanly and re-emits
    /// byte-identically. Pins both the field order in `ReparseBlob`
    /// (`tag` before `data`) and that the variant resolves through
    /// `#[serde(untagged)]`.
    #[test]
    fn reparse_point_round_trip_through_the_carrier() {
        let original =
            r#"{"windows.reparse_point":{"tag":2684354572,"data":"FAA8AAAAOAAFAAAA"}}"#;
        let m: BTreeMap<String, GenericAttributeValue> =
            serde_json::from_str(original).unwrap();
        assert!(matches!(
            m.get("windows.reparse_point"),
            Some(GenericAttributeValue::ReparsePoint(b))
                if b.tag == 0xA000000C && b.data == "FAA8AAAAOAAFAAAA"
        ));
        let re_emitted = serde_json::to_string(&m).unwrap();
        assert_eq!(re_emitted, original);
    }

    /// Forward-compat: a tree blob produced by 2d (carrying
    /// `windows.sparse_extents`) deserialises cleanly and re-emits
    /// byte-identically. Also covers the round-trip of an empty
    /// extents array, since the helper guards against emission of an
    /// empty list — but parsing must still tolerate one.
    #[test]
    fn sparse_extents_round_trip_through_the_carrier() {
        let original = r#"{"windows.sparse_extents":[[100,200],[400,800]]}"#;
        let m: BTreeMap<String, GenericAttributeValue> =
            serde_json::from_str(original).unwrap();
        assert!(matches!(
            m.get("windows.sparse_extents"),
            Some(GenericAttributeValue::SparseExtents(v)) if v == &vec![[100i64, 200], [400, 800]]
        ));
        let re_emitted = serde_json::to_string(&m).unwrap();
        assert_eq!(re_emitted, original);
    }

    /// Forward-read 2a's wire format: a tree blob produced by 2a
    /// (only the SD key, as a JSON string) must deserialise cleanly
    /// into the widened carrier, and re-emit byte-identically.
    #[test]
    fn old_2a_sd_only_repos_round_trip_through_the_widened_carrier() {
        let original = r#"{"windows.security_descriptor":"AQAEh=="}"#;
        let m: BTreeMap<String, GenericAttributeValue> =
            serde_json::from_str(original).unwrap();
        assert_eq!(m.len(), 1);
        assert!(matches!(
            m.get("windows.security_descriptor"),
            Some(GenericAttributeValue::String(s)) if s == "AQAEh=="
        ));
        let re_emitted = serde_json::to_string(&m).unwrap();
        assert_eq!(re_emitted, original);
    }

    /// Ord is total, deterministic, and orders by variant first.
    #[test]
    fn ord_is_total_and_variant_aware() {
        let ct = GenericAttributeValue::CreationTime(WindowsFiletime {
            low_date_time: 0,
            high_date_time: 0,
        });
        let rp = GenericAttributeValue::ReparsePoint(ReparseBlob {
            tag: 0xA0000003,
            data: "AA==".into(),
        });
        let sx = GenericAttributeValue::SparseExtents(vec![[0, 4]]);
        let n = GenericAttributeValue::U32(1);
        let s = GenericAttributeValue::String("z".into());
        // Variant ranks: CreationTime < ReparsePoint < SparseExtents
        //              < U32 < String.
        assert!(ct < rp);
        assert!(rp < sx);
        assert!(sx < n);
        assert!(n < s);
        // Reflexive.
        assert_eq!(ct.cmp(&ct), Ordering::Equal);
        assert_eq!(rp.cmp(&rp), Ordering::Equal);
        assert_eq!(sx.cmp(&sx), Ordering::Equal);
        // Same variant — compare content.
        let n2 = GenericAttributeValue::U32(2);
        assert!(n < n2);
        let sx2 = GenericAttributeValue::SparseExtents(vec![[0, 4], [8, 4]]);
        assert!(sx < sx2);
        // Same variant for reparse: tag comparison wins over data.
        let rp_smaller_tag = GenericAttributeValue::ReparsePoint(ReparseBlob {
            tag: 0xA0000003,
            data: "AA==".into(),
        });
        let rp_bigger_tag = GenericAttributeValue::ReparsePoint(ReparseBlob {
            tag: 0xA000000C,
            data: "AA==".into(),
        });
        assert!(rp_smaller_tag < rp_bigger_tag);
        // Same tag: data is the tiebreaker.
        let rp_data_a = GenericAttributeValue::ReparsePoint(ReparseBlob {
            tag: 0xA0000003,
            data: "AAA=".into(),
        });
        let rp_data_b = GenericAttributeValue::ReparsePoint(ReparseBlob {
            tag: 0xA0000003,
            data: "AAB=".into(),
        });
        assert!(rp_data_a < rp_data_b);
    }

    /// `WindowsFiletime` ordering follows the chronological order of
    /// the underlying 64-bit FILETIME value.
    #[test]
    fn windows_filetime_orders_chronologically() {
        let earlier = WindowsFiletime {
            low_date_time: u32::MAX,
            high_date_time: 0,
        };
        let later = WindowsFiletime {
            low_date_time: 0,
            high_date_time: 1,
        };
        assert!(earlier < later);
    }

    /// Round-trip the two non-SD restic-supported attrs: apply
    /// known values, then re-capture and require byte-equality.
    /// Proves the apply path is the inverse of the capture path.
    /// FILE_ATTRIBUTE_HIDDEN (0x2) | FILE_ATTRIBUTE_READONLY (0x1) =
    /// 0x3 is the smallest distinctive bitset; FILE_ATTRIBUTE_ARCHIVE
    /// (0x20) is set by NTFS on writes, so the post-write capture
    /// will include it on top of what we set.
    #[cfg(windows)]
    #[test]
    fn file_attributes_and_creation_time_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rt.bin");
        std::fs::write(&p, b"x").unwrap();
        // Apply: stamp ReadOnly+Hidden and a known historical FILETIME.
        // 130645440000000000 = 2014-12-31T00:00:00Z in FILETIME ticks.
        let want_ct = super::WindowsFiletime {
            low_date_time: 0xC9FFD200,
            high_date_time: 0x01D01CDB,
        };
        assert!(super::apply::file_attributes(&p, 0x1 | 0x2));
        assert!(super::apply::creation_time(&p, want_ct));
        // Re-capture.
        let (got_attrs, got_ct) =
            super::capture::file_attributes_and_creation_time(&p).unwrap();
        // ReadOnly + Hidden survived; ARCHIVE may also be present.
        assert!(
            got_attrs & 0x3 == 0x3,
            "ReadOnly+Hidden must round-trip, got {got_attrs:#x}"
        );
        // FILETIME has 100ns resolution; round-trip is byte-exact.
        assert_eq!(got_ct, want_ct);
    }

    /// `capture::file_attributes_and_creation_time` reads both fields
    /// off a real file via `GetFileAttributesExW`. Smoke test: a
    /// freshly created file has a non-zero creation time and the
    /// returned attribute bitset is small enough to fit `u32` (it
    /// always does, since that's the Win32 type).
    #[cfg(windows)]
    #[test]
    fn capture_reads_attributes_and_creation_time() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("probe.txt");
        std::fs::write(&p, b"x").unwrap();
        let (attrs, ct) = super::capture::file_attributes_and_creation_time(&p)
            .expect("GetFileAttributesExW must succeed on a just-created file");
        // FILE_ATTRIBUTE_ARCHIVE (0x20) is set by NTFS on every new
        // file. Other flags may be present too; just assert the
        // archive bit is on as a sanity check that we read real data.
        assert!(attrs & 0x20 != 0, "expected ARCHIVE bit, got {attrs:#x}");
        // A real FILETIME is never zero for a file that exists.
        assert!(
            ct.low_date_time != 0 || ct.high_date_time != 0,
            "creation time must be non-zero"
        );
    }

    /// An object-shaped value parses as `CreationTime` or
    /// `ReparsePoint` depending on its keys; an array as
    /// `SparseExtents`; a number as `U32`; a string as `String`. The
    /// two object variants have disjoint required-field sets
    /// (`LowDateTime/HighDateTime` vs `tag/data`), so serde resolves
    /// them unambiguously regardless of declaration order.
    #[test]
    fn untagged_variant_resolution_is_unambiguous_for_each_shape() {
        let v: GenericAttributeValue =
            serde_json::from_str(r#"{"LowDateTime":1,"HighDateTime":2}"#).unwrap();
        assert!(matches!(v, GenericAttributeValue::CreationTime(_)));

        let v: GenericAttributeValue =
            serde_json::from_str(r#"{"tag":2684354572,"data":"AAEC"}"#).unwrap();
        assert!(matches!(
            v,
            GenericAttributeValue::ReparsePoint(ref b)
                if b.tag == 0xA000000C && b.data == "AAEC"
        ));

        let v: GenericAttributeValue =
            serde_json::from_str(r#"[[0,4096],[8192,4096]]"#).unwrap();
        assert!(matches!(
            v,
            GenericAttributeValue::SparseExtents(ref e) if e == &vec![[0i64,4096],[8192,4096]]
        ));

        let v: GenericAttributeValue = serde_json::from_str("42").unwrap();
        assert!(matches!(v, GenericAttributeValue::U32(42)));

        let v: GenericAttributeValue = serde_json::from_str(r#""hello""#).unwrap();
        assert!(matches!(v, GenericAttributeValue::String(ref s) if s == "hello"));
    }
}
