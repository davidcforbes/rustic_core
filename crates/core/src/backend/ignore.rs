pub mod mapper;
pub use mapper::LocalSourceSaveOptions;

use std::{
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
};

use bytesize::ByteSize;
use crossbeam_channel::unbounded;
use derive_setters::Setters;
use ignore::{DirEntry, WalkBuilder, WalkState};
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
        // Size enumeration runs concurrently with `entries()` (spawned
        // in `Archiver::archive`) and only feeds the progress bar's
        // total length — it's a best-effort speculative pass. We use
        // the same parallel walker so it doesn't lag the real walk on
        // deeply-nested workloads.
        let threads = walker_thread_count(self.save_opts.walker_threads);
        let size = std::sync::atomic::AtomicU64::new(0);
        let size_ref = &size;
        if threads <= 1 {
            for entry in self.builder.build() {
                if let Err(err) = entry.and_then(|e| e.metadata()).map(|m| {
                    if !m.is_dir() {
                        size_ref.fetch_add(m.len(), std::sync::atomic::Ordering::Relaxed);
                    }
                }) {
                    warn!("ignoring error {err}");
                }
            }
        } else {
            self.builder.clone().threads(threads).build_parallel().run(|| {
                Box::new(|result| {
                    match result.and_then(|e| e.metadata()) {
                        Ok(m) if !m.is_dir() => {
                            size_ref.fetch_add(m.len(), std::sync::atomic::Ordering::Relaxed);
                        }
                        Ok(_) => {}
                        Err(err) => warn!("ignoring error {err}"),
                    }
                    WalkState::Continue
                })
            });
        }
        Ok(Some(size.into_inner()))
    }

    /// Iterate over the entries of the local source.
    ///
    /// # Returns
    ///
    /// An iterator over the entries of the local source. The iterator
    /// yields entries in depth-first lexicographic order by path; with
    /// the default multi-threaded walker this is achieved by collecting
    /// the full `ignore::WalkParallel` output into a `Vec` and sorting
    /// before yielding (downstream `TreeIterator` in `archiver/tree.rs`
    /// requires this ordering — out-of-order entries would repeatedly
    /// EndTree/NewTree the same subtree and corrupt the tree blob). The
    /// trade-off is peak memory proportional to entry count, which is
    /// acceptable for the workloads this code targets; tests can opt
    /// into the legacy streaming behaviour by setting
    /// `LocalSourceSaveOptions::walker_threads = Some(1)`.
    fn entries(&self) -> Self::Iter {
        let threads = walker_thread_count(self.save_opts.walker_threads);
        let inner: Box<dyn Iterator<Item = Result<DirEntry, ignore::Error>> + Send> = if threads <= 1 {
            // Legacy single-threaded path: stream entries straight from
            // the walker. `ignore::Walk` already sorts via
            // `sort_by_file_path(Path::cmp)` set in `LocalSource::new`.
            Box::new(self.builder.build())
        } else {
            // Phase A multi-threaded path: parallel walk + collect + sort.
            //
            // Per-thread callbacks push entries through a crossbeam
            // unbounded channel (lock-free fast path; matches the
            // existing channel-as-producer-output pattern in
            // `packer.rs:9`). After `WalkParallel::run` returns, all
            // callback senders are dropped, the receiver disconnects,
            // and we drain into a `Vec` for the sort.
            let (tx, rx) = unbounded();
            self.builder
                .clone()
                .threads(threads)
                .build_parallel()
                .run(|| {
                    let tx = tx.clone();
                    Box::new(move |result| {
                        // A `Err` here means the receiver was dropped
                        // (cancellation). Silently stop walking — the
                        // consumer is already gone.
                        if tx.send(result).is_err() {
                            return WalkState::Quit;
                        }
                        WalkState::Continue
                    })
                });
            drop(tx); // close the channel so `rx.into_iter()` terminates
            let mut collected: Vec<Result<DirEntry, ignore::Error>> = rx.into_iter().collect();
            collected.sort_by(|a, b| match (a, b) {
                (Ok(a), Ok(b)) => a.path().cmp(b.path()),
                // Push Errs after Oks; preserves the historical
                // behaviour of warn-and-skip without re-ordering valid
                // entries around them.
                (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                (Err(_), Err(_)) => std::cmp::Ordering::Equal,
            });
            Box::new(collected.into_iter())
        };
        LocalSourceWalker {
            walker: inner,
            save_opts: self.save_opts,
            map_threads: threads,
            chunk_buf: std::collections::VecDeque::new(),
            #[cfg(windows)]
            pending_ads: std::collections::VecDeque::new(),
            #[cfg(windows)]
            reparse_skip: Vec::new(),
        }
    }
}

/// Resolve the requested walker thread count.
///
/// - `Some(n)` → `n.clamp(1, 32)`.
/// - `None` → `available_parallelism()` clamped to `[1, 32]`, with a
///   conservative fallback of `1` if the platform refuses to answer.
///
/// The upper bound of 32 matches the original Phase A design note:
/// past ~32 readdir threads NTFS contention dominates and the marginal
/// throughput drops sharply on the AppData workload that motivated
/// kopia-0dr.63.1. Operators wanting more can pass an explicit value;
/// the cap is intentionally soft and only applies to the auto path.
fn walker_thread_count(opt: Option<usize>) -> usize {
    if let Some(n) = opt {
        return n.clamp(1, 32);
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 32)
}

/// kopia-0dr.63.11: how many sorted entries `next()` maps per parallel
/// chunk. A chunk is `map_group`'d across the rayon pool then drained in
/// order, so only one chunk's worth of built `Node`s is resident at a time
/// (~a few MB) — not all N (which was the 6.9 GB blowup). 4096 gives every
/// pool thread plenty of work while keeping the window tiny.
const NODE_BUILD_CHUNK: usize = 4096;

/// kopia-0dr.63.11: one DirEntry's node-build result, produced in parallel
/// inside a chunk's `map_group`. The host entry plus any ADS siblings stay
/// together so host-before-stream order is preserved on flatten;
/// `is_reparse_dir` drives the sequential reparse-skip filter.
struct MappedGroup {
    /// Sort key = host path. `None` for walk errors / the dropped walk-root
    /// (they carry no reparse semantics and a single mapped error / nothing).
    sort_key: Option<PathBuf>,
    is_reparse_dir: bool,
    entries: Vec<RusticResult<ReadSourceEntry<OpenFile>>>,
}

/// Build a [`MappedGroup`] for one walker result — `map_entry` (the SD +
/// node-build) + ADS enumeration. Mirrors the single-threaded `next()`
/// per-entry logic so the parallel and legacy paths emit identical entry
/// sets (the `phase_a_tests` equivalence test guards this). Pure given
/// `save_opts` (`Copy`) + the entry, so it runs safely on the rayon pool.
fn map_group(
    save_opts: LocalSourceSaveOptions,
    result: Result<DirEntry, ignore::Error>,
) -> MappedGroup {
    let entry = match result {
        Ok(e) => e,
        Err(err) => {
            let mapped = Err(RusticError::with_source(
                ErrorKind::Internal,
                "Failed to get next entry from walk iterator.",
                err,
            )
            .ask_report());
            return MappedGroup {
                sort_key: None,
                is_reparse_dir: false,
                entries: vec![mapped],
            };
        }
    };
    // Skip the walk root (depth-0 dir) — matches next()'s root skip.
    if entry.depth() == 0 && entry.file_type().is_some_and(|t| t.is_dir()) {
        return MappedGroup {
            sort_key: None,
            is_reparse_dir: false,
            entries: Vec::new(),
        };
    }
    let path = entry.path().to_path_buf();
    let host = match save_opts.map_entry(entry) {
        Ok(h) => h,
        Err(err) => {
            let mapped = Err(RusticError::with_source(
                ErrorKind::Internal,
                "Failed to map Directory entry to ReadSourceEntry.",
                err,
            )
            .ask_report());
            return MappedGroup {
                sort_key: Some(path),
                is_reparse_dir: false,
                entries: vec![mapped],
            };
        }
    };
    #[cfg(windows)]
    let (is_reparse_dir, entries) = {
        use crate::backend::node::{win_reparse, NodeType};
        let is_reparse_dir = matches!(host.node.node_type, NodeType::Dir)
            && host
                .node
                .meta
                .generic_attributes
                .contains_key(win_reparse::REPARSE_KEY);
        let mut siblings: Vec<RusticResult<ReadSourceEntry<OpenFile>>> = Vec::new();
        if matches!(host.node.node_type, NodeType::File) {
            if let Some(ref open) = host.open {
                let host_path = open.path.clone();
                let host_node = host.node.clone();
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
                            siblings.push(Ok(ReadSourceEntry {
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
        let mut entries = vec![Ok(host)];
        entries.extend(siblings);
        (is_reparse_dir, entries)
    };
    #[cfg(not(windows))]
    let (is_reparse_dir, entries): (bool, Vec<RusticResult<ReadSourceEntry<OpenFile>>>) =
        (false, vec![Ok(host)]);
    MappedGroup {
        sort_key: Some(path),
        is_reparse_dir,
        entries,
    }
}

// The boxed walker (a `Vec::IntoIter` or `ignore::Walk`) doesn't
// implement Debug, so the wrapper can't derive it either.
#[allow(missing_debug_implementations)]
pub struct LocalSourceWalker {
    /// The walk iterator. In the multi-threaded path this is a
    /// `std::vec::IntoIter` over the sorted parallel-walk output; in
    /// the `walker_threads = Some(1)` legacy path it is the original
    /// `ignore::Walk` straight through.
    walker: Box<dyn Iterator<Item = Result<DirEntry, ignore::Error>> + Send>,
    /// The save options to use.
    save_opts: LocalSourceSaveOptions,
    /// kopia-0dr.63.11: node-build thread count. `> 1` enables the chunked
    /// parallel node-build (map_entry across the rayon pool, bounded
    /// window via `chunk_buf`); `<= 1` keeps the legacy single-threaded
    /// lazy map (the deterministic oracle path).
    map_threads: usize,
    /// kopia-0dr.63.11: drained-in-order buffer of the current parallel
    /// chunk's mapped entries (host + ADS siblings). Refilled by
    /// `map_group`'ing the next `NODE_BUILD_CHUNK` walk entries across the
    /// pool. Only the parallel path uses it.
    chunk_buf: std::collections::VecDeque<RusticResult<ReadSourceEntry<OpenFile>>>,
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
        // kopia-0dr.63.11: chunked parallel node-build. Map the next
        // NODE_BUILD_CHUNK sorted walk entries across the rayon pool
        // (map_entry is now SD-only after the redundant-syscall
        // elimination, and SD parallelises ~11.5x), drain in order. Only a
        // single chunk's worth of built Nodes is resident — no 6.9 GB
        // collect. Reparse-skip uses the persistent prefix stack across
        // chunks; the sorted (depth-first) order makes that exact.
        if self.map_threads > 1 {
            use rayon::prelude::*;
            loop {
                if let Some(entry) = self.chunk_buf.pop_front() {
                    return Some(entry);
                }
                let chunk: Vec<Result<DirEntry, ignore::Error>> =
                    self.walker.by_ref().take(NODE_BUILD_CHUNK).collect();
                if chunk.is_empty() {
                    return None;
                }
                let save_opts = self.save_opts;
                let groups: Vec<MappedGroup> = chunk
                    .into_par_iter()
                    .map(|de| map_group(save_opts, de))
                    .collect();
                for g in groups {
                    #[cfg(windows)]
                    if let Some(ref p) = g.sort_key {
                        // Pop prefixes whose subtree we've left; drop strict
                        // descendants of an active reparse (junction) dir.
                        self.reparse_skip.retain(|pfx| p.starts_with(pfx));
                        if self
                            .reparse_skip
                            .iter()
                            .any(|pfx| p.starts_with(pfx) && p != pfx.as_path())
                        {
                            continue;
                        }
                        if g.is_reparse_dir {
                            self.reparse_skip.push(p.clone());
                        }
                    }
                    self.chunk_buf.extend(g.entries);
                }
            }
        }

        // --- legacy single-threaded path (map_threads <= 1) ---
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

#[cfg(test)]
mod phase_a_tests {
    //! Phase A (kopia-0dr.63.1) — verify the multi-threaded
    //! [`ignore::WalkParallel`] path produces the same sorted entry
    //! set as the legacy single-threaded [`ignore::Walk`] path.
    //!
    //! The downstream [`crate::archiver::tree::TreeIterator`] requires
    //! depth-first lexicographic ordering; if `LocalSource::entries`
    //! were to yield out-of-order entries the tree archiver would
    //! repeatedly open/close subtrees and produce a corrupt tree blob.
    //! These tests guard the ordering invariant on synthetic fixtures
    //! large enough that single-thread vs parallel-walk-then-sort
    //! exercises real merge behaviour.
    use super::*;
    use crate::Excludes;
    use std::fs;
    use tempfile::tempdir;

    fn build_fixture(root: &Path) {
        // 50 sibling directories, each with 20 files. 1000 entries +
        // ancestor dirs — small enough to be cheap, big enough to land
        // on multiple walker threads in the parallel path.
        for d in 0..50 {
            let sub = root.join(format!("dir_{d:02}"));
            fs::create_dir_all(&sub).unwrap();
            for f in 0..20 {
                fs::write(sub.join(format!("file_{f:02}.bin")), b"x").unwrap();
            }
        }
    }

    fn collect_paths(opts: LocalSourceSaveOptions, root: &Path) -> Vec<PathBuf> {
        let excludes = Excludes::default();
        let filter_opts = LocalSourceFilterOptions::default();
        let src = LocalSource::new(opts, &excludes, &filter_opts, &[root]).unwrap();
        src.entries()
            .filter_map(|r| r.ok())
            .map(|e| e.path)
            .collect()
    }

    #[test]
    fn parallel_walk_matches_single_thread_order() {
        let tmp = tempdir().unwrap();
        build_fixture(tmp.path());

        let serial =
            collect_paths(LocalSourceSaveOptions::default().walker_threads(Some(1usize)), tmp.path());
        let parallel = collect_paths(
            LocalSourceSaveOptions::default().walker_threads(Some(8usize)),
            tmp.path(),
        );

        assert_eq!(
            serial, parallel,
            "Phase A multi-thread walk must yield same sorted output as single-thread Walk"
        );
        assert!(
            serial.len() >= 1000,
            "fixture should produce >=1000 entries, got {}",
            serial.len()
        );
    }

    // kopia-0dr.63.11: the chunked parallel node-build moved map_entry +
    // ADS into a rayon par-map and does reparse-skip as a cross-chunk
    // prefix filter. Guard those parallel-specific paths against the
    // single-threaded oracle on the two cases the plain-file fixture can't
    // exercise: an NTFS ADS sibling (duplicate host-path entry) and a
    // junction whose descendants must be skipped. Both creatable
    // non-elevated (ADS via a `:stream` path, junction via `mklink /J`).
    #[cfg(windows)]
    #[test]
    fn parallel_matches_single_thread_with_ads_and_junction() {
        let tmp = tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(root.join("host.txt"), b"host body").unwrap();
        std::fs::write(root.join("host.txt:adsname"), b"stream body").unwrap();

        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("inside.txt"), b"x").unwrap();
        let link = root.join("link");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                link.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J should create the junction");

        let serial = collect_paths(
            LocalSourceSaveOptions::default().walker_threads(Some(1usize)),
            root,
        );
        let parallel = collect_paths(
            LocalSourceSaveOptions::default().walker_threads(Some(8usize)),
            root,
        );

        assert_eq!(
            serial, parallel,
            "chunked parallel ADS+junction walk must match single-thread output"
        );
        let host_count = serial
            .iter()
            .filter(|p| p.file_name().is_some_and(|n| n == "host.txt"))
            .count();
        assert!(
            host_count >= 2,
            "expected host + ADS sibling for host.txt, got {host_count}"
        );
        assert!(
            !serial
                .iter()
                .any(|p| p.components().any(|c| c.as_os_str() == "link")
                    && p.file_name().is_some_and(|n| n == "inside.txt")),
            "junction descendants must be skipped"
        );
    }

    #[test]
    fn parallel_size_matches_single_thread() {
        // Same fixture; assert that the parallel `size()` path sums to
        // the same value as the serial path. Files are 1 byte each so
        // the total equals the file count (dirs contribute 0).
        let tmp = tempdir().unwrap();
        build_fixture(tmp.path());

        let excludes = Excludes::default();
        let filter_opts = LocalSourceFilterOptions::default();
        let serial_src = LocalSource::new(
            LocalSourceSaveOptions::default().walker_threads(Some(1usize)),
            &excludes,
            &filter_opts,
            &[tmp.path()],
        )
        .unwrap();
        let parallel_src = LocalSource::new(
            LocalSourceSaveOptions::default().walker_threads(Some(8usize)),
            &excludes,
            &filter_opts,
            &[tmp.path()],
        )
        .unwrap();

        assert_eq!(serial_src.size().unwrap(), parallel_src.size().unwrap());
    }

    #[test]
    fn walker_thread_count_clamps() {
        // Auto path: None → in [1, 32].
        let auto = walker_thread_count(None);
        assert!((1..=32).contains(&auto), "auto thread count out of bounds: {auto}");

        // Explicit override is clamped to [1, 32].
        assert_eq!(walker_thread_count(Some(0)), 1);
        assert_eq!(walker_thread_count(Some(1)), 1);
        assert_eq!(walker_thread_count(Some(8)), 8);
        assert_eq!(walker_thread_count(Some(32)), 32);
        assert_eq!(walker_thread_count(Some(64)), 32);
        assert_eq!(walker_thread_count(Some(usize::MAX)), 32);
    }
}
