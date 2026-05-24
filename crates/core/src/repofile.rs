use std::{borrow::Cow, ops::Deref, str::FromStr};

use jiff::{
    Timestamp, Zoned,
    civil::Time,
    fmt::temporal::{DateTimePrinter, Pieces},
    tz::TimeZone,
};
use serde::{Deserialize, Deserializer, Serialize, de, de::DeserializeOwned};
use serde_with::{DeserializeAs, SerializeAs};

pub(crate) mod configfile;
pub(crate) mod indexfile;
pub(crate) mod keyfile;
pub(crate) mod packfile;
pub(crate) mod snapshotfile;

/// Marker trait for repository files which are stored as JSON
pub trait RepoFile: Serialize + DeserializeOwned + Sized + Send + Sync + 'static {
    /// The [`FileType`] associated with the repository file
    const TYPE: FileType;
    /// Indicate whether the files are stored encrypted
    const ENCRYPTED: bool = true;
    /// The Id type associated with the repository file
    type Id: RepoId;
}

/// Marker trait for Ids which identify repository files
pub trait RepoId: Deref<Target = Id> + From<Id> + Sized + Copy + Send + Sync + 'static {
    /// The [`FileType`] associated with Id type
    const TYPE: FileType;
}

#[macro_export]
/// Generate newtypes for `Id`s identifying Repository files
macro_rules! impl_repoid {
    ($a:ident, $b: expr) => {
        $crate::define_new_id_struct!($a, concat!("repository file of type", stringify!($b)));
        impl $crate::repofile::RepoId for $a {
            const TYPE: FileType = $b;
        }
    };
}

#[macro_export]
/// Generate newtypes for `Id`s identifying Repository files implementing `RepoFile`
macro_rules! impl_repofile {
    ($a:ident, $b: expr, $c: ty) => {
        $crate::impl_repoid!($a, $b);
        impl RepoFile for $c {
            const TYPE: FileType = $b;
            type Id = $a;
        }
    };
}

/// helper struct for serializing and deserializing
///
/// This is used in order to stay compatible with the restic repository format.
/// It can be directly used via `serde_as` or by using its methods for parsing and printing.
#[derive(Debug, Clone, Copy)]
pub struct RusticTime;

impl RusticTime {
    /// best-effort parsing of a string into a `Zoned`.
    ///
    /// # Errors
    pub fn parse(
        s: &str,
        default_time: Time,
        default_zone: TimeZone,
    ) -> Result<Zoned, jiff::Error> {
        if let Ok(zoned) = Zoned::from_str(s) {
            return Ok(zoned);
        }
        let pieces = Pieces::parse(&s)?;
        let time = pieces.time().unwrap_or(default_time);
        let dt = pieces.date().to_datetime(time);
        let zone = pieces.to_time_zone()?.unwrap_or_else(|| {
            pieces
                .to_numeric_offset()
                .map_or_else(|| default_zone, TimeZone::fixed)
        });
        dt.to_zoned(zone)
    }

    /// Best-effort parsing of a string into a `Zoned`.
    ///
    /// Uses 00:00 if no time is given and the system timezone if no zone is given.
    ///
    /// # Errors
    pub fn parse_system(s: &str) -> Result<Zoned, jiff::Error> {
        Self::parse(s, Time::MIN, TimeZone::system())
    }

    /// Best-effort parsing of a string into a `Zoned`.
    ///
    /// Uses 00:00 if no time is given and UTC if no zone is given.
    ///
    /// # Errors
    pub fn parse_utc(s: &str) -> Result<Zoned, jiff::Error> {
        Self::parse(s, Time::MIN, TimeZone::UTC)
    }

    /// Display a `Zoned` in a restic-compatible way, i.e. with offset, but without timezone
    #[must_use]
    pub fn to_string(source: &Zoned) -> String {
        DateTimePrinter::new().timestamp_with_offset_to_string(&source.timestamp(), source.offset())
    }
}

impl SerializeAs<Zoned> for RusticTime {
    fn serialize_as<S>(source: &Zoned, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&Self::to_string(source))
    }
}

impl<'de> DeserializeAs<'de, Zoned> for RusticTime {
    fn deserialize_as<D>(deserializer: D) -> Result<Zoned, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse_utc(&s).map_err(de::Error::custom)
    }
}

impl SerializeAs<Timestamp> for RusticTime {
    fn serialize_as<S>(source: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let offset = TimeZone::system().to_offset(*source);
        serializer.collect_str(&source.display_with_offset(offset).to_string())
    }
}

impl<'de> DeserializeAs<'de, Timestamp> for RusticTime {
    fn deserialize_as<D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        Timestamp::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    //! kopia-pl3 Track 1 — falsify the hypothesis that `RusticTime`'s
    //! asymmetric serde (serialize via `display_with_offset(system_tz)`,
    //! deserialize via `Timestamp::deserialize`) breaks byte-identity on
    //! parent-passthrough Nodes during Phase E shadow runs.
    //!
    //! If these tests PASS: hypothesis ruled out; the Phase E divergence
    //! lives elsewhere (ancestor-restat fidelity, deleted_set, ADS order,
    //! etc.) — proceed to diff-snapshots triangulation.
    //!
    //! If these tests FAIL: the fix lives here in `RusticTime`. Use
    //! jiff's own serde uniformly on both sides (drop the
    //! `display_with_offset` custom path).
    use super::*;
    use jiff::Timestamp;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct TsWrap {
        #[serde_as(as = "RusticTime")]
        ts: Timestamp,
    }

    /// Walk a Timestamp through the SAME serialize/deserialize path the
    /// parent tree blob uses, then through it again. The bytes from the
    /// second serialization must equal the bytes from the first — that
    /// is what makes parent passthrough byte-identical on Node.mtime.
    fn assert_round_trip_stable(ts: Timestamp, label: &str) {
        let wrap0 = TsWrap { ts };
        let json0 = serde_json::to_string(&wrap0)
            .unwrap_or_else(|e| panic!("{label}: first serialize failed: {e}"));
        let wrap1: TsWrap = serde_json::from_str(&json0)
            .unwrap_or_else(|e| panic!("{label}: deserialize failed: {e} (input: {json0})"));
        let json1 = serde_json::to_string(&wrap1)
            .unwrap_or_else(|e| panic!("{label}: second serialize failed: {e}"));
        assert_eq!(
            json0, json1,
            "{label}: round-trip is not byte-identical (jiff Timestamp value preserved: {})",
            wrap1.ts == wrap0.ts
        );
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_simple() {
        // Midnight UTC, no sub-second precision.
        let ts: Timestamp = "2026-05-24T00:00:00Z".parse().unwrap();
        assert_round_trip_stable(ts, "midnight_utc_no_subsec");
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_with_nanos() {
        // Full nanosecond precision — what NTFS FILETIME can produce
        // when converted through SystemTime → jiff::Timestamp.
        let ts: Timestamp = "2026-05-24T10:11:12.345678901Z".parse().unwrap();
        assert_round_trip_stable(ts, "nanosecond_precision");
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_dst_summer() {
        // Summer (EDT, UTC-04:00) — when cycle 1 + 2 of the kopia-pl3
        // soak actually ran.
        let ts: Timestamp = "2026-07-15T14:30:00Z".parse().unwrap();
        assert_round_trip_stable(ts, "dst_summer_edt");
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_dst_winter() {
        // Winter (EST, UTC-05:00) — a file last modified in January.
        let ts: Timestamp = "2026-01-15T14:30:00Z".parse().unwrap();
        assert_round_trip_stable(ts, "dst_winter_est");
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_dst_transition_spring() {
        // Spring-forward day (2026-03-09 in US): 2:00 AM jumps to 3:00 AM.
        // Test a Timestamp just before, at, and just after the wall-clock
        // jump.
        for s in [
            "2026-03-09T06:30:00Z", // 01:30 EST (before transition)
            "2026-03-09T07:30:00Z", // 02:30 (skipped wall-clock window)
            "2026-03-09T08:30:00Z", // 04:30 EDT (after transition)
        ] {
            let ts: Timestamp = s.parse().unwrap();
            assert_round_trip_stable(ts, &format!("spring_forward_{s}"));
        }
    }

    #[test]
    fn timestamp_round_trip_is_byte_identical_dst_transition_fall() {
        // Fall-back day (2026-11-02 in US): 2:00 AM repeats as 1:00 AM.
        // The ambiguous wall-clock window is the dangerous one for a
        // local-offset serializer.
        for s in [
            "2026-11-02T05:30:00Z", // 01:30 EDT (first occurrence)
            "2026-11-02T06:30:00Z", // 01:30 EST (second occurrence, after fallback)
            "2026-11-02T07:30:00Z", // 02:30 EST (after transition)
        ] {
            let ts: Timestamp = s.parse().unwrap();
            assert_round_trip_stable(ts, &format!("fall_back_{s}"));
        }
    }

    #[test]
    fn timestamp_round_trip_handles_epoch_zero() {
        // Edge case: SystemTime::UNIX_EPOCH converts to Timestamp(0).
        // Files with truly absent mtime hit this.
        let ts = Timestamp::UNIX_EPOCH;
        assert_round_trip_stable(ts, "unix_epoch_zero");
    }
}

// Part of public API
use crate::Id;

pub use {
    crate::{
        backend::{
            ALL_FILE_TYPES, FileType,
            node::{Metadata, Node, NodeType},
        },
        blob::{ALL_BLOB_TYPES, BlobType, tree::Tree},
    },
    configfile::{Chunker, ConfigFile},
    indexfile::{IndexBlob, IndexFile, IndexId, IndexPack},
    keyfile::{KeyFile, KeyId, MasterKey},
    packfile::{HeaderEntry, PackHeader, PackHeaderLength, PackHeaderRef, PackId},
    snapshotfile::{
        DeleteOption, PathList, SnapshotFile, SnapshotId, SnapshotModification, SnapshotSummary,
        StringList,
    },
};
