//! Restic-compatible value carrier for `Metadata.generic_attributes`
//! (kopia-0dr.53 — rustback-filecopy increment 2b).
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

/// One restic `generic_attributes` value — covers every shape restic
/// v0.18.1 actually emits, and parses any of them transparently.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GenericAttributeValue {
    /// `windows.creation_time` — the FILETIME of the file's creation.
    CreationTime(WindowsFiletime),
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

impl Ord for GenericAttributeValue {
    /// Total order: by variant tag first (matching declaration
    /// discriminants), then by content. Stable, deterministic, and
    /// independent of insertion order.
    fn cmp(&self, other: &Self) -> Ordering {
        fn rank(v: &GenericAttributeValue) -> u8 {
            match v {
                GenericAttributeValue::CreationTime(_) => 0,
                GenericAttributeValue::U32(_) => 1,
                GenericAttributeValue::String(_) => 2,
            }
        }
        match rank(self).cmp(&rank(other)) {
            Ordering::Equal => match (self, other) {
                (Self::CreationTime(a), Self::CreationTime(b)) => a.cmp(b),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The on-disk shape must be byte-identical to what restic v0.18.1
    /// emits for the same three keys. Restic-format compatibility for
    /// 2b hinges on this test (and its bit-compat oracle in
    /// `rustback-filecopy`).
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
            "windows.security_descriptor".into(),
            GenericAttributeValue::String("AQAEh==".into()),
        );
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"windows.creation_time":{"LowDateTime":2864434397,"HighDateTime":287454020},"windows.file_attributes":34,"windows.security_descriptor":"AQAEh=="}"#
        );
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
        let n = GenericAttributeValue::U32(1);
        let s = GenericAttributeValue::String("z".into());
        // Variant ranks: CreationTime < U32 < String.
        assert!(ct < n);
        assert!(n < s);
        // Reflexive.
        assert_eq!(ct.cmp(&ct), Ordering::Equal);
        // Same variant — compare content.
        let n2 = GenericAttributeValue::U32(2);
        assert!(n < n2);
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

    /// An object-shaped value parses as `CreationTime`; a number as
    /// `U32`; a string as `String`. The variant order in the enum is
    /// the order serde tries — placing `CreationTime` first ensures
    /// objects can never fall through to a wrong variant.
    #[test]
    fn untagged_variant_resolution_is_unambiguous_for_each_shape() {
        let v: GenericAttributeValue =
            serde_json::from_str(r#"{"LowDateTime":1,"HighDateTime":2}"#).unwrap();
        assert!(matches!(v, GenericAttributeValue::CreationTime(_)));

        let v: GenericAttributeValue = serde_json::from_str("42").unwrap();
        assert!(matches!(v, GenericAttributeValue::U32(42)));

        let v: GenericAttributeValue = serde_json::from_str(r#""hello""#).unwrap();
        assert!(matches!(v, GenericAttributeValue::String(ref s) if s == "hello"));
    }
}
