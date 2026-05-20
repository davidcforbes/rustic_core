pub mod mapper;
pub use mapper::LocalSourceSaveOptions;

use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
};

use bytesize::ByteSize;
use derive_setters::Setters;
use ignore::{Walk, WalkBuilder};
use log::warn;
use serde_with::{DisplayFromStr, serde_as};

#[cfg(not(windows))]
use std::num::TryFromIntError;

use crate::{
    Excludes,
    backend::{ReadSource, ReadSourceEntry, ReadSourceOpen},
    error::{ErrorKind, RusticError, RusticResult},
};

/// [`IgnoreErrorKind`] describes the errors that can be returned by a Ignore action in Backends
#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum IgnoreErrorKind {
    #[cfg(all(not(windows), not(target_os = "openbsd")))]
    /// Error getting xattrs for `{path:?}`: `{source:?}`
    ErrorXattr {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Error reading link target for `{path:?}`: `{source:?}`
    ErrorLink {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(not(windows))]
    /// Error converting ctime `{ctime}` and `ctime_nsec` `{ctime_nsec}` to Utc Timestamp: `{source:?}`
    CtimeConversionToTimestampFailed {
        ctime: i64,
        ctime_nsec: i64,
        source: TryFromIntError,
    },
    /// Error acquiring metadata for `{name}`: `{source:?}`
    AcquiringMetadataFailed { name: String, source: ignore::Error },
    /// time error
    JiffError(#[from] jiff::Error),
}

pub(crate) type IgnoreResult<T> = Result<T, IgnoreErrorKind>;

/// A [`LocalSource`] is a source from local paths which is used to be read from (i.e. to backup it).
#[derive(Debug)]
pub struct LocalSource {
    /// The walk builder.
    builder: WalkBuilder,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
}

#[serde_as]
#[cfg_attr(feature = "clap", derive(clap::Parser))]
#[cfg_attr(feature = "merge", derive(conflate::Merge))]
#[derive(serde::Deserialize, serde::Serialize, Default, Clone, Debug, Setters)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
#[setters(into)]
#[non_exhaustive]
/// [`LocalSourceFilterOptions`] allow to filter a local source by various criteria.
pub struct LocalSourceFilterOptions {
    /// Ignore files based on .gitignore files
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub git_ignore: bool,

    /// Do not require a git repository to apply git-ignore rule
    #[cfg_attr(feature = "clap", clap(long))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub no_require_git: bool,

    /// Treat the provided filename like a .gitignore file (can be specified multiple times)
    #[cfg_attr(
        feature = "clap",
        clap(long = "custom-ignorefile", value_name = "FILE")
    )]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub custom_ignorefiles: Vec<String>,

    /// Exclude contents of directories containing this filename (can be specified multiple times)
    #[cfg_attr(feature = "clap", clap(long, value_name = "FILE"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_present: Vec<String>,

    /// Exclude files/directories having the given extended attribute set (can be specified multiple times)
    #[cfg_attr(feature = "clap", clap(long, value_name = "XATTR"))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::vec::overwrite_empty))]
    pub exclude_if_xattr: Vec<String>,

    /// Exclude other file systems, don't cross filesystem boundaries and subvolumes
    #[cfg_attr(feature = "clap", clap(long, short = 'x'))]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::bool::overwrite_false))]
    pub one_file_system: bool,

    /// Maximum size of files to be backed up. Larger files will be excluded.
    #[cfg_attr(feature = "clap", clap(long, value_name = "SIZE"))]
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[cfg_attr(feature = "merge", merge(strategy = conflate::option::overwrite_none))]
    pub exclude_larger_than: Option<ByteSize>,
}

impl LocalSource {
    /// Create a local source from [`LocalSourceSaveOptions`], [`LocalSourceFilterOptions`] and backup path(s).
    ///
    /// # Arguments
    ///
    /// * `save_opts` - The [`LocalSourceSaveOptions`] to use.
    /// * `filter_opts` - The [`LocalSourceFilterOptions`] to use.
    /// * `backup_paths` - The backup path(s) to use.
    ///
    /// # Returns
    ///
    /// The created local source.
    ///
    /// # Errors
    ///
    /// * If the a glob pattern could not be added to the override builder.
    /// * If a glob file could not be read.
    #[allow(clippy::too_many_lines)]
    pub fn new(
        save_opts: LocalSourceSaveOptions,
        excludes: &Excludes,
        filter_opts: &LocalSourceFilterOptions,
        backup_paths: &[impl AsRef<Path>],
    ) -> RusticResult<Self> {
        let mut walk_builder = WalkBuilder::new(&backup_paths[0]);

        for path in &backup_paths[1..] {
            _ = walk_builder.add(path);
        }

        let overrides = excludes.as_override()?;

        for file in &filter_opts.custom_ignorefiles {
            _ = walk_builder.add_custom_ignore_filename(file);
        }

        _ = walk_builder
            .follow_links(false)
            .hidden(false)
            .ignore(false)
            .git_ignore(filter_opts.git_ignore)
            .git_exclude(filter_opts.git_ignore)
            .require_git(!filter_opts.no_require_git)
            .sort_by_file_path(Path::cmp)
            .same_file_system(filter_opts.one_file_system)
            .max_filesize(filter_opts.exclude_larger_than.map(|s| s.as_u64()))
            .overrides(overrides);

        let exclude_if_present = filter_opts.exclude_if_present.clone();
        let exclude_if_xattr: Vec<OsString> = filter_opts
            .exclude_if_xattr
            .iter()
            .map(OsString::from)
            .collect();

        if !exclude_if_xattr.is_empty() {
            #[cfg(any(windows, target_os = "openbsd"))]
            warn!("exclude-if-xattr is not supported on this platform");
            #[cfg(not(any(windows, target_os = "openbsd")))]
            if !xattr::SUPPORTED_PLATFORM {
                warn!("exclude-if-xattr is not supported on this platform");
            }
        }

        let needs_entry_filter = !exclude_if_present.is_empty() || !exclude_if_xattr.is_empty();

        if needs_entry_filter {
            _ = walk_builder.filter_entry(move |entry| {
                // exclude-if-present: skip directories containing a marker file
                if !exclude_if_present.is_empty()
                    && let Some(tpe) = entry.file_type()
                    && tpe.is_dir()
                    && exclude_if_present
                        .iter()
                        .any(|file| entry.path().join(file).exists())
                {
                    return false;
                }

                // exclude-if-xattr: skip entries that have a matching xattr
                #[cfg(not(any(windows, target_os = "openbsd")))]
                if xattr::SUPPORTED_PLATFORM && !exclude_if_xattr.is_empty() {
                    match xattr::list(entry.path()) {
                        Ok(mut attrs) => {
                            if attrs.any(|attr| exclude_if_xattr.contains(&attr)) {
                                return false;
                            }
                        }
                        Err(err) => {
                            warn!(
                                "Error reading xattrs for {}, not excluding: {err}",
                                entry.path().display()
                            );
                        }
                    }
                }

                true
            });
        }

        let builder = walk_builder;

        Ok(Self { builder, save_opts })
    }
}

#[derive(Debug)]
/// Describes an open file from the local backend.
///
/// On Windows, `stream` may be set to a named NTFS Alternate Data
/// Stream of `path`; in that case `open()` appends `:<stream>:$DATA`
/// to the path and `CreateFileW` (under `File::open`) opens the
/// stream rather than the host file's body. See `node/win_ads.rs`
/// and `LocalSourceWalker` for the ADS sibling-node mechanism
/// (kopia-0dr.53 increment 2b).
pub struct OpenFile {
    path: PathBuf,
    #[cfg(windows)]
    stream: Option<String>,
}

impl OpenFile {
    /// Open the host file's default data stream.
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            #[cfg(windows)]
            stream: None,
        }
    }

    /// Open a named NTFS Alternate Data Stream of the host file.
    #[cfg(windows)]
    pub(crate) fn for_stream(host: PathBuf, stream: String) -> Self {
        Self {
            path: host,
            stream: Some(stream),
        }
    }
}

impl ReadSourceOpen for OpenFile {
    type Reader = File;

    /// Open the file from the local backend.
    ///
    /// On Windows, if `stream` is `Some`, the path is suffixed with
    /// `:<stream>:$DATA` before being passed to `File::open`;
    /// `CreateFileW` interprets that syntax and returns a handle to
    /// the named NTFS ADS rather than the host file's body.
    ///
    /// # Returns
    ///
    /// The read handle to the file from the local backend.
    ///
    /// # Errors
    ///
    /// * If the file could not be opened.
    fn open(self) -> RusticResult<Self::Reader> {
        #[cfg(windows)]
        let path: PathBuf = if let Some(stream) = self.stream {
            let mut p = self.path.into_os_string();
            p.push(":");
            p.push(&stream);
            p.push(":$DATA");
            PathBuf::from(p)
        } else {
            self.path
        };
        #[cfg(not(windows))]
        let path: PathBuf = self.path;

        File::open(&path).map_err(|err| {
            RusticError::with_source(
                ErrorKind::InputOutput,
                "Failed to open file at `{path}`. Please make sure the file exists and is accessible.",
                err,
            )
            .attach_context("path", path.display().to_string())
        })
    }
}

impl ReadSource for LocalSource {
    type Open = OpenFile;
    type Iter = LocalSourceWalker;

    /// Get the size of the local source.
    ///
    /// # Returns
    ///
    /// The size of the local source or `None` if the size could not be determined.
    ///
    /// # Errors
    ///
    /// * If the size could not be determined.
    fn size(&self) -> RusticResult<Option<u64>> {
        let mut size = 0;
        for entry in self.builder.build() {
            if let Err(err) = entry.and_then(|e| e.metadata()).map(|m| {
                size += if m.is_dir() { 0 } else { m.len() };
            }) {
                warn!("ignoring error {err}");
            }
        }
        Ok(Some(size))
    }

    /// Iterate over the entries of the local source.
    ///
    /// # Returns
    ///
    /// An iterator over the entries of the local source.
    fn entries(&self) -> Self::Iter {
        LocalSourceWalker {
            walker: self.builder.build(),
            save_opts: self.save_opts,
            #[cfg(windows)]
            pending_ads: std::collections::VecDeque::new(),
            #[cfg(windows)]
            reparse_skip: Vec::new(),
        }
    }
}

// Walk doesn't implement Debug
#[allow(missing_debug_implementations)]
pub struct LocalSourceWalker {
    /// The walk iterator.
    walker: Walk,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
    /// Windows: NTFS Alternate Data Stream sibling entries buffered
    /// for the next `next()` calls. Each regular-file entry yielded
    /// by the underlying walker can produce N additional sibling
    /// entries (one per named stream). The queue is FIFO so the host
    /// file's entry is always yielded before its ADS siblings;
    /// downstream `TreeArchiver::add_file` preserves that order in
    /// the parent Tree's `Vec<Node>`. (kopia-0dr.53 increment 2b.)
    #[cfg(windows)]
    pending_ads: std::collections::VecDeque<RusticResult<ReadSourceEntry<OpenFile>>>,
    /// Windows: filesystem-path prefixes of reparse-tagged directories
    /// whose contents must be skipped during the walk. `ignore::Walk`
    /// recurses into junctions (and other reparse-tagged directories)
    /// because it sees them as regular Dirs via `Metadata::is_dir()`;
    /// without this guard we would over-count by walking the
    /// junction's target. Each time we emit a Dir Node carrying
    /// `windows.reparse_point` we push its filesystem path here; the
    /// next-loop skips any subsequent entry whose path is strictly
    /// under one of these prefixes. Prefixes are popped lazily once
    /// the walker leaves their subtree (depth-first walk order
    /// guarantees this works without an explicit depth counter).
    /// (kopia-4rf — increment 2c.)
    #[cfg(windows)]
    reparse_skip: Vec<PathBuf>,
}

impl Iterator for LocalSourceWalker {
    type Item = RusticResult<ReadSourceEntry<OpenFile>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Drain buffered ADS siblings before pulling another walker
        // entry. On non-Windows this branch is removed by the cfg.
        #[cfg(windows)]
        if let Some(buffered) = self.pending_ads.pop_front() {
            return Some(buffered);
        }

        // Loop until we yield a non-skipped entry (or run out of
        // walker output). Skipping is needed only on Windows for
        // descendants of reparse-tagged directories (kopia-4rf).
        let item = loop {
            let raw = match self.walker.next() {
                // ignore root dir, i.e. an entry with depth 0 of type dir
                Some(Ok(entry)) if entry.depth() == 0 && entry.file_type().unwrap().is_dir() => {
                    self.walker.next()
                }
                item => item,
            };

            // Windows reparse-point recursion guard: drop any entry
            // strictly under an active reparse-skip prefix. Also
            // pop prefixes the walker has already moved above.
            #[cfg(windows)]
            if let Some(Ok(ref de)) = raw {
                let p = de.path();
                // Pop any prefix whose subtree we've left.
                self.reparse_skip.retain(|pfx| p.starts_with(pfx));
                // Skip descendants (the prefix itself was emitted
                // when we pushed it, so we only skip when `p != pfx`).
                if self
                    .reparse_skip
                    .iter()
                    .any(|pfx| p.starts_with(pfx) && p != pfx.as_path())
                {
                    continue;
                }
            }

            break raw.map(|e| {
                self.save_opts
                    .map_entry(e.map_err(|err| {
                        RusticError::with_source(
                            ErrorKind::Internal,
                            "Failed to get next entry from walk iterator.",
                            err,
                        )
                        .ask_report()
                    })?)
                    .map_err(|err| {
                        RusticError::with_source(
                            ErrorKind::Internal,
                            "Failed to map Directory entry to ReadSourceEntry.",
                            err,
                        )
                        .ask_report()
                    })
            });
        };

        // Windows: after yielding an entry, decide whether to push
        // it as a new reparse-skip prefix and/or to enumerate its
        // NTFS Alternate Data Streams.
        #[cfg(windows)]
        if let Some(Ok(ref entry)) = item {
            use crate::backend::node::{win_reparse, NodeType};

            // Reparse-tagged directories: junctions and other
            // dir-shaped reparse points. Push the path so the walker
            // doesn't follow into the link target. We don't need a
            // similar guard for SYMLINK-tagged hosts because
            // `WalkBuilder::follow_links(false)` already stops
            // descent into real symlinks.
            if matches!(entry.node.node_type, NodeType::Dir)
                && entry
                    .node
                    .meta
                    .generic_attributes
                    .contains_key(win_reparse::REPARSE_KEY)
            {
                self.reparse_skip.push(entry.path.clone());
            }

            // After a regular File entry, enumerate any NTFS ADS
            // attached to it and buffer one sibling entry per
            // stream. Errors enumerating streams are non-fatal
            // (warn + skip) — the host file's backup still proceeds
            // normally.
            if matches!(entry.node.node_type, NodeType::File) {
                if let Some(ref open) = entry.open {
                    let host_path = open.path.clone();
                    let host_node = entry.node.clone();
                    match crate::backend::node::win_ads::enumerate(&host_path) {
                        Ok(streams) => {
                            for (stream_name, size) in streams {
                                let ads_node = crate::backend::ignore::mapper::ads_sibling_node(
                                    &host_node,
                                    &stream_name,
                                    size,
                                );
                                let ads_open = OpenFile::for_stream(
                                    host_path.clone(),
                                    stream_name.as_str().to_string(),
                                );
                                self.pending_ads.push_back(Ok(ReadSourceEntry {
                                    path: host_path.clone(),
                                    node: ads_node,
                                    open: Some(ads_open),
                                }));
                            }
                        }
                        Err(err) => warn!(
                            "ignoring ADS enumeration failure on {}: {err}",
                            host_path.display()
                        ),
                    }
                }
            }
        }

        item
    }
}
