use crate::fs;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs::FileType;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, RwLock};
use std::time::Instant;
use tracing::{instrument, trace};
use wax::{Any, LinkBehavior, Pattern};

#[cfg(feature = "glob-cache")]
pub use crate::glob_cache::GlobCache;
pub use crate::glob_error::GlobError;
pub use wax::{self, Glob};

static GLOBAL_NEGATIONS: LazyLock<RwLock<Vec<&'static str>>> = LazyLock::new(|| {
    RwLock::new(vec![
        "**/.{git,svn}/**",
        "**/.DS_Store",
        "**/node_modules/**",
    ])
});

/// Add global negated patterns to all glob sets and walking operations.
pub fn add_global_negations<I>(patterns: I)
where
    I: IntoIterator<Item = &'static str>,
{
    let mut negations = GLOBAL_NEGATIONS.write().unwrap();
    negations.extend(patterns);
}

/// Set global negated patterns to be used by all glob sets and walking operations.
/// This will overwrite any existing global negated patterns.
pub fn set_global_negations<I>(patterns: I)
where
    I: IntoIterator<Item = &'static str>,
{
    let mut negations = GLOBAL_NEGATIONS.write().unwrap();
    negations.clear();
    negations.extend(patterns);
}

/// Match values against a set of glob patterns.
pub struct GlobSet<'glob> {
    /// Positive patterns (e.g., `*.js`, `src/*.ts`, `**/*.rs`).
    expressions: Any<'glob>,

    /// All negative patterns for matching (e.g., `!*.log`, `!temp/*`, `!node_modules/**`).
    negations: Any<'glob>,

    /// Roots of unbounded negative patterns, used for fast directory traversal skipping.
    /// For example, `foo/*/bar/**/*` produces root `foo/*/bar`.
    /// This allows skipping entire subtrees without allocating a trailing slash.
    negation_traversal_roots: Option<Any<'glob>>,

    enabled: bool,
}

impl GlobSet<'_> {
    /// Create a new glob set from the list of patterns.
    /// Negated patterns must start with `!`.
    pub fn new<'new, I, V>(patterns: I) -> Result<GlobSet<'new>, GlobError>
    where
        I: IntoIterator<Item = &'new V> + Debug,
        V: AsRef<str> + 'new + ?Sized,
    {
        let (expressions, negations) = split_patterns(patterns);

        GlobSet::new_split(expressions, negations)
    }

    /// Create a new owned/static glob set from the list of patterns.
    /// Negated patterns must start with `!`.
    pub fn new_owned<'new, I, V>(patterns: I) -> Result<GlobSet<'static>, GlobError>
    where
        I: IntoIterator<Item = &'new V> + Debug,
        V: AsRef<str> + 'new + ?Sized,
    {
        let (expressions, negations) = split_patterns(patterns);

        GlobSet::new_split_owned(expressions, negations)
    }

    /// Create a new glob set with explicitly separate expressions and negations.
    /// Negated patterns must not start with `!`.
    pub fn new_split<'new, I1, V1, I2, V2>(
        expressions: I1,
        negations: I2,
    ) -> Result<GlobSet<'new>, GlobError>
    where
        I1: IntoIterator<Item = &'new V1>,
        V1: AsRef<str> + 'new + ?Sized,
        I2: IntoIterator<Item = &'new V2>,
        V2: AsRef<str> + 'new + ?Sized,
    {
        let mut ex = vec![];
        let mut ng = vec![];
        let mut ng_roots = vec![];
        let mut count = 0;

        for pattern in expressions.into_iter() {
            ex.push(create_glob(pattern.as_ref())?);
            count += 1;
        }

        for pattern in negations.into_iter() {
            let pattern_str = pattern.as_ref();
            // All negation patterns go into the main negations list
            ng.push(create_glob(pattern_str)?);
            // Additionally, extract roots of unbounded patterns for fast traversal skipping.
            // For example, `foo/*/bar/**/*` produces root `foo/*/bar` which can match
            // directories without a trailing slash.
            if let Some(root) = root_of_unbounded_pattern(pattern_str)
                && !root.is_empty()
            {
                ng_roots.push(create_glob(root)?);
            }
            count += 1;
        }

        let global_negations = GLOBAL_NEGATIONS.read().unwrap();
        for pattern in global_negations.iter() {
            ng.push(create_glob(pattern)?);
            if let Some(root) = root_of_unbounded_pattern(pattern)
                && !root.is_empty()
            {
                ng_roots.push(create_glob(root)?);
            }
            count += 1;
        }

        Ok(GlobSet {
            expressions: wax::any(ex).unwrap(),
            negations: wax::any(ng).unwrap(),
            negation_traversal_roots: if ng_roots.is_empty() {
                None
            } else {
                Some(wax::any(ng_roots).unwrap())
            },
            enabled: count > 0,
        })
    }

    /// Create a new owned/static glob set with explicitly separate expressions and negations.
    /// Negated patterns must not start with `!`.
    pub fn new_split_owned<'new, I1, V1, I2, V2>(
        expressions: I1,
        negations: I2,
    ) -> Result<GlobSet<'static>, GlobError>
    where
        I1: IntoIterator<Item = &'new V1>,
        V1: AsRef<str> + 'new + ?Sized,
        I2: IntoIterator<Item = &'new V2>,
        V2: AsRef<str> + 'new + ?Sized,
    {
        let mut ex = vec![];
        let mut ng = vec![];
        let mut ng_roots = vec![];
        let mut count = 0;

        for pattern in expressions.into_iter() {
            ex.push(create_glob(pattern.as_ref())?.into_owned());
            count += 1;
        }

        for pattern in negations.into_iter() {
            let pattern_str = pattern.as_ref();
            // All negation patterns go into the main negations list
            ng.push(create_glob(pattern_str)?.into_owned());
            // Additionally, extract roots of unbounded patterns for fast traversal skipping
            if let Some(root) = root_of_unbounded_pattern(pattern_str)
                && !root.is_empty()
            {
                ng_roots.push(create_glob(root)?.into_owned());
            }
            count += 1;
        }

        let global_negations = GLOBAL_NEGATIONS.read().unwrap();
        for pattern in global_negations.iter() {
            ng.push(create_glob(pattern)?.into_owned());
            if let Some(root) = root_of_unbounded_pattern(pattern)
                && !root.is_empty()
            {
                ng_roots.push(create_glob(root)?.into_owned());
            }
            count += 1;
        }

        Ok(GlobSet {
            expressions: wax::any(ex).unwrap(),
            negations: wax::any(ng).unwrap(),
            negation_traversal_roots: if ng_roots.is_empty() {
                None
            } else {
                Some(wax::any(ng_roots).unwrap())
            },
            enabled: count > 0,
        })
    }

    /// Return true if the path matches the negated patterns.
    pub fn is_excluded<P: AsRef<OsStr>>(&self, path: P) -> bool {
        self.negations.is_match(path.as_ref())
    }

    /// Return true if the path matches the non-negated patterns.
    pub fn is_included<P: AsRef<OsStr>>(&self, path: P) -> bool {
        self.expressions.is_match(path.as_ref())
    }

    /// Return true if the path matches the glob patterns,
    /// while taking into account negated patterns.
    pub fn matches<P: AsRef<OsStr>>(&self, path: P) -> bool {
        if !self.enabled {
            return false;
        }

        let path = path.as_ref();

        if self.is_excluded(path) {
            return false;
        }

        self.is_included(path)
    }

    /// Return true if the directory should be traversed (i.e., does NOT match
    /// any unbounded negative pattern root). When false, the entire subtree
    /// should be skipped during traversal.
    pub(crate) fn should_traverse_dir<P: AsRef<OsStr>>(&self, path: P) -> bool {
        self.negation_traversal_roots
            .as_ref()
            .is_none_or(|roots| !roots.is_match(path.as_ref()))
    }
}

/// Parse and create a [`Glob`] instance from the borrowed string pattern.
/// If parsing fails, a [`GlobError`] is returned.
#[inline]
pub fn create_glob(pattern: &str) -> Result<Glob<'_>, GlobError> {
    Glob::new(pattern).map_err(|error| GlobError::Create {
        glob: pattern.to_owned(),
        error: Box::new(error),
    })
}

/// Return true if the provided string looks like a glob pattern.
/// This is not exhaustive and may be inaccurate.
#[inline]
pub fn is_glob<T: AsRef<str> + Debug>(value: T) -> bool {
    let value = value.as_ref();

    if value.contains("**") || value.starts_with('!') {
        return true;
    }

    let single_values = vec!['*', '?'];
    let paired_values = vec![('{', '}'), ('[', ']')];
    let mut bytes = value.bytes();
    let mut is_escaped = |index: usize| {
        if index == 0 {
            return false;
        }

        bytes.nth(index - 1).unwrap_or(b' ') == b'\\'
    };

    for single in single_values {
        if !value.contains(single) {
            continue;
        }

        if let Some(index) = value.find(single)
            && !is_escaped(index)
        {
            return true;
        }
    }

    for (open, close) in paired_values {
        if !value.contains(open) || !value.contains(close) {
            continue;
        }

        if let Some(index) = value.find(open)
            && !is_escaped(index)
        {
            return true;
        }
    }

    false
}

/// Normalize a glob-based file path to use forward slashes. If the path contains
/// invalid UTF-8 characters, a [`GlobError`] is returned.
#[inline]
pub fn normalize<T: AsRef<Path>>(path: T) -> Result<String, GlobError> {
    let path = path.as_ref();

    match path.to_str() {
        Some(p) => Ok(p.replace('\\', "/")),
        None => Err(GlobError::InvalidPath {
            path: path.to_path_buf(),
        }),
    }
}

/// Split a list of glob patterns into separate non-negated and negated patterns.
/// Negated patterns must start with `!`.
#[inline]
pub fn split_patterns<'glob, I, V>(patterns: I) -> (Vec<&'glob str>, Vec<&'glob str>)
where
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    let mut expressions = vec![];
    let mut negations = vec![];

    for pattern in patterns {
        let mut negate = false;
        let mut value = pattern.as_ref();

        while value.starts_with('!') || value.starts_with('/') {
            if let Some(neg) = value.strip_prefix('!') {
                negate = true;
                value = neg;
            } else if let Some(exp) = value.strip_prefix('/') {
                value = exp;
            }
        }

        value = value.trim_start_matches("./");

        if negate {
            negations.push(value);
        } else {
            expressions.push(value);
        }
    }

    (expressions, negations)
}

/// Walk the file system starting from the provided directory, and return all files and directories
/// that match the provided glob patterns. Use [`walk_files`] if you only want to return files.
#[inline]
#[instrument]
pub fn walk<'glob, P, I, V>(base_dir: P, patterns: I) -> Result<Vec<PathBuf>, GlobError>
where
    P: AsRef<Path> + Debug,
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    let base_dir = base_dir.as_ref();
    let instant = Instant::now();
    let mut paths = vec![];

    trace!(dir = ?base_dir, globs = ?patterns, "Finding files");

    let (expressions, mut negations) = split_patterns(patterns);
    negations.extend(GLOBAL_NEGATIONS.read().unwrap().iter());

    for expression in expressions {
        for entry in create_glob(expression)?
            .walk_with_behavior(base_dir, LinkBehavior::ReadFile)
            .not(negations.clone())
            .unwrap()
        {
            match entry {
                Ok(e) => {
                    paths.push(e.into_path());
                }
                Err(_) => {
                    // Will crash if the file doesn't exist
                    continue;
                }
            };
        }
    }

    trace!(dir = ?base_dir, "Found {} in {:?}", paths.len(), instant.elapsed());

    Ok(paths)
}

/// Walk the file system starting from the provided directory, and return all files
/// that match the provided glob patterns. Use [`walk`] if you need directories as well.
#[inline]
pub fn walk_files<'glob, P, I, V>(base_dir: P, patterns: I) -> Result<Vec<PathBuf>, GlobError>
where
    P: AsRef<Path> + Debug,
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    let paths = walk(base_dir, patterns)?;

    Ok(paths
        .into_iter()
        .filter(|p| p.is_file())
        .collect::<Vec<_>>())
}

/// Options to customize walking behavior.
#[derive(Debug)]
pub struct GlobWalkOptions {
    pub cache: bool,
    pub ignore_dot_dirs: bool,
    pub ignore_dot_files: bool,
    pub log_results: bool,
    pub only_dirs: bool,
    pub only_files: bool,
}

impl GlobWalkOptions {
    /// Cache the results globally.
    pub fn cache(mut self) -> Self {
        self.cache = true;
        self
    }

    /// Only return directories.
    pub fn dirs(mut self) -> Self {
        self.only_dirs = true;
        self
    }

    /// Only return files.
    pub fn files(mut self) -> Self {
        self.only_files = true;
        self
    }

    /// Control directories that start with a `.`.
    pub fn dot_dirs(mut self, ignore: bool) -> Self {
        self.ignore_dot_dirs = ignore;
        self
    }

    /// Control files that start with a `.`.
    pub fn dot_files(mut self, ignore: bool) -> Self {
        self.ignore_dot_files = ignore;
        self
    }

    /// Log the results.
    pub fn log_results(mut self) -> Self {
        self.log_results = true;
        self
    }
}

impl Default for GlobWalkOptions {
    fn default() -> Self {
        Self {
            cache: false,
            ignore_dot_dirs: true,
            ignore_dot_files: false,
            log_results: false,
            only_dirs: false,
            only_files: false,
        }
    }
}

/// Walk the file system starting from the provided directory, and return all files and directories
/// that match the provided glob patterns.
#[inline]
pub fn walk_fast<'glob, P, I, V>(base_dir: P, patterns: I) -> Result<Vec<PathBuf>, GlobError>
where
    P: AsRef<Path> + Debug,
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    walk_fast_with_options(base_dir, patterns, GlobWalkOptions::default())
}

/// Walk the file system starting from the provided directory, and return all files and directories
/// that match the provided glob patterns, and customize further with the provided options.
#[inline]
#[instrument]
pub fn walk_fast_with_options<'glob, P, I, V>(
    base_dir: P,
    patterns: I,
    options: GlobWalkOptions,
) -> Result<Vec<PathBuf>, GlobError>
where
    P: AsRef<Path> + Debug,
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    let mut paths = vec![];

    for (dir, mut patterns) in partition_patterns(base_dir, patterns) {
        patterns.sort();

        // Only run if the feature is enabled
        #[cfg(feature = "glob-cache")]
        if options.cache && !crate::envx::is_test() {
            paths.extend(
                GlobCache::instance()
                    .cache(&dir, &patterns, |d, p| internal_walk(d, p, &options))?,
            );

            continue;
        }

        paths.extend(internal_walk(&dir, &patterns, &options)?);
    }

    Ok(paths)
}

fn internal_walk(
    dir: &Path,
    patterns: &[String],
    options: &GlobWalkOptions,
) -> Result<Vec<PathBuf>, GlobError> {
    trace!(dir = ?dir, globs = ?patterns, "Finding files");

    let instant = Instant::now();
    let globset = GlobSet::new(patterns)?;
    let traverse = should_traverse_deep(patterns);
    let mut paths = vec![];

    let mut add_path =
        // Prefer passing the file path to add_path because path.is_dir() / .is_file()
        // makes another call to the file system, which is expensive during large recursive
        // walks.
        |file_type: FileType, path: PathBuf, base_dir: &Path, globset: &GlobSet<'_>| {
            if file_type.is_file()
                && (options.only_dirs || options.ignore_dot_files && is_hidden_dot(&path))
            {
                return;
            }

            if file_type.is_dir()
                && (options.only_files || options.ignore_dot_dirs && is_hidden_dot(&path))
            {
                return;
            }

            if let Ok(suffix) = path.strip_prefix(base_dir)
                && globset.matches(suffix)
            {
                paths.push(path);
            }
        };

    if traverse {
        let ignore_dot_dirs = options.ignore_dot_dirs;
        let base_dir_for_walk = dir.to_path_buf();

        // jwalk::WalkDir requires the function have a static lifetime, so it
        // can be dispatched across rayon threads, but we want to parameterize the walk
        // on the contents of the passed in globs for performance.
        //
        // The canonical ways to do this are to copy of the globset to move it into the closure.
        // However, this is a hot path in large repos, so to avoid the overhead of cloning,
        // we transume the lifetime of the reference to 'static.
        //
        // This risky, but should be safe because the last use of the glob should be
        // before the iterator is dropped, so this reference will not outlive its original scope.
        let globset_static: &GlobSet<'static> = unsafe { std::mem::transmute(&globset) };

        for entry in jwalk::WalkDir::new(dir)
            .follow_links(false)
            .skip_hidden(false)
            .parallelism(jwalk::Parallelism::RayonNewPool(0))
            .process_read_dir(move |depth, path, _state, children| {
                // Only ignore nested hidden dirs, but do not ignore
                // if the root dir is hidden, as globs resolve from it
                if ignore_dot_dirs
                    && depth.is_some_and(|d| d > 0)
                    && path.is_dir()
                    && is_hidden_dot(path)
                {
                    children.retain(|_| false);
                    return;
                }

                // Skip directories that match unbounded negative patterns
                // This avoids traversing entire subtrees like node_modules/**
                if let Ok(suffix) = path.strip_prefix(&base_dir_for_walk) {
                    if !globset_static.should_traverse_dir(suffix) {
                        children.retain(|_| false);
                    }
                }
            })
            .into_iter()
            .flatten()
        {
            add_path(entry.file_type, entry.path(), dir, &globset);
        }

        // Manually drop the globset to ensure that the compiler doesn't
        // optimize it out while our unsafely transmuted reference is still in use.
        drop(globset);
    } else {
        for entry in fs::read_dir(dir)? {
            add_path(
                fs::dir_entry_file_type(&entry)?,
                entry.path(),
                dir,
                &globset,
            );
        }
    }

    trace!(
        dir = ?dir,
        results = ?if options.log_results {
            Some(&paths)
        } else {
            None
        },
        "Found {} in {:?}",
        paths.len(),
        instant.elapsed(),
    );

    Ok(paths)
}

/// Partition a list of patterns and a base directory into buckets, keyed by the common
/// parent directory. This helps to alleviate over-globbing on large directories.
pub fn partition_patterns<'glob, P, I, V>(
    base_dir: P,
    patterns: I,
) -> BTreeMap<PathBuf, Vec<String>>
where
    P: AsRef<Path> + Debug,
    I: IntoIterator<Item = &'glob V> + Debug,
    V: AsRef<str> + 'glob + ?Sized,
{
    let base_dir = base_dir.as_ref();
    let mut partitions = BTreeMap::<PathBuf, Vec<String>>::new();

    // Sort patterns from smallest to longest glob,
    // so that we can create the necessary buckets correctly
    let mut patterns = patterns.into_iter().map(|p| p.as_ref()).collect::<Vec<_>>();
    patterns.sort_by_key(|a| a.len());

    // Separate positive patterns and negations
    let mut positive_patterns = vec![];
    let mut negation_patterns = vec![];
    let mut global_negations = vec![];

    for pattern in patterns {
        if pattern.starts_with("!**") {
            global_negations.push(pattern.to_owned());
        } else if let Some(suffix) = pattern.strip_prefix('!') {
            negation_patterns.push(suffix.trim_start_matches("./"));
        } else {
            positive_patterns.push(pattern.trim_start_matches("./"));
        }
    }

    // First pass: create partitions from positive patterns only
    for pattern in positive_patterns {
        let mut dir = base_dir.to_path_buf();
        let mut glob_parts = vec![];
        let mut found = false;

        let parts = pattern.split('/').collect::<Vec<_>>();
        let last_index = parts.len() - 1;

        for (index, part) in parts.into_iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if found || index == last_index || is_glob(part) {
                glob_parts.push(part);
                found = true;
            } else {
                dir = dir.join(part);

                if partitions.contains_key(&dir) {
                    found = true;
                }
            }
        }

        let glob = glob_parts.join("/");
        partitions.entry(dir).or_default().push(glob);
    }

    // Second pass: distribute negations to all overlapping partitions
    for neg_pattern in negation_patterns {
        // Parse the negation pattern to find its directory prefix
        let mut neg_dir = base_dir.to_path_buf();
        let mut neg_glob_parts = vec![];
        let mut found = false;

        let parts = neg_pattern.split('/').collect::<Vec<_>>();
        let last_index = parts.len() - 1;

        for (index, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if found || index == last_index || is_glob(part) {
                neg_glob_parts.push(*part);
                found = true;
            } else {
                neg_dir = neg_dir.join(part);
            }
        }

        // Add this negation to all partitions where it could apply:
        // 1. If partition is an ancestor of neg_dir (negation is inside partition's subtree)
        // 2. If partition equals neg_dir
        // 3. If partition is a descendant of neg_dir (partition is inside negation's scope)
        for (partition_dir, partition_patterns) in partitions.iter_mut() {
            if let Some(relative_neg) =
                compute_relative_negation(base_dir, partition_dir, &neg_dir, &neg_glob_parts)
            {
                partition_patterns.push(format!("!{relative_neg}"));
            }
        }
    }

    // Apply global negations to all partitions
    if !global_negations.is_empty() {
        partitions.iter_mut().for_each(|(_key, value)| {
            value.extend(global_negations.clone());
        });
    }

    partitions
}

/// Compute the relative negation pattern for a partition, if the negation applies to it.
///
/// Returns Some(relative_pattern) if the negation overlaps with the partition, None otherwise.
fn compute_relative_negation(
    _base_dir: &Path,
    partition_dir: &Path,
    neg_dir: &Path,
    neg_glob_parts: &[&str],
) -> Option<String> {
    // Case 1: partition_dir is an ancestor of or equal to neg_dir
    // e.g., partition=/root, neg=/root/build => neg should be "build/**"
    // e.g., partition=/root/src, neg=/root/src/tests => neg should be "tests/**"
    if let Ok(relative) = neg_dir.strip_prefix(partition_dir) {
        let mut parts: Vec<&str> = relative
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        parts.extend(neg_glob_parts.iter().copied());
        return Some(parts.join("/"));
    }

    // Case 2: neg_dir is an ancestor of partition_dir
    // e.g., partition=/root/build, neg=/root => negation applies to entire partition
    // The negation's glob part should be adjusted relative to the partition
    if let Ok(relative) = partition_dir.strip_prefix(neg_dir) {
        // The partition is inside the negation's scope
        // We need to check if the negation's glob would match paths in this partition
        let relative_parts: Vec<&str> = relative
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();

        // If neg_glob_parts starts with ** or contains patterns that could match the relative path,
        // we need to include this negation
        if neg_glob_parts.first().is_some_and(|p| p.starts_with("**")) {
            // Unbounded negation applies to all descendants
            return Some(neg_glob_parts.join("/"));
        }

        // Check if the glob prefix could match the partition's relative path
        // e.g., neg_glob_parts = ["foo*", "**"], relative_parts = ["foo", "bar"]
        // "foo*" could match "foo", so we need to include this negation
        if could_glob_match_path_prefix(neg_glob_parts, &relative_parts) {
            // Compute remaining glob parts after consuming matched path components
            let remaining = compute_remaining_glob(neg_glob_parts, &relative_parts);
            if !remaining.is_empty() {
                return Some(remaining);
            }
        }
    }

    None
}

/// Check if a glob pattern prefix could match a path prefix.
/// e.g., ["foo*", "**"] could match ["foo", "bar"] because "foo*" matches "foo"
fn could_glob_match_path_prefix(glob_parts: &[&str], path_parts: &[&str]) -> bool {
    if glob_parts.is_empty() || path_parts.is_empty() {
        return false;
    }

    // Check each glob part against corresponding path part
    for (i, glob_part) in glob_parts.iter().enumerate() {
        if glob_part.starts_with("**") {
            // ** matches any number of path components
            return true;
        }

        if i >= path_parts.len() {
            // More glob parts than path parts, can't match
            return false;
        }

        let path_part = path_parts[i];

        // Check if this glob part could match this path part
        if !could_glob_part_match(glob_part, path_part) {
            return false;
        }
    }

    true
}

/// Check if a single glob pattern part could match a path part.
/// This is a simplified check that handles common cases.
fn could_glob_part_match(glob_part: &str, path_part: &str) -> bool {
    if glob_part == path_part {
        return true;
    }

    // Handle simple wildcards
    if glob_part == "*" {
        return true;
    }

    // Handle prefix wildcards like "foo*"
    if let Some(prefix) = glob_part.strip_suffix('*') {
        if path_part.starts_with(prefix) {
            return true;
        }
    }

    // Handle suffix wildcards like "*foo"
    if let Some(suffix) = glob_part.strip_prefix('*') {
        if path_part.ends_with(suffix) {
            return true;
        }
    }

    // Handle patterns with wildcards in the middle like "foo*bar"
    if glob_part.contains('*') {
        // Simple check: if it has a wildcard and shares a common prefix/suffix, it might match
        let parts: Vec<&str> = glob_part.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            if path_part.starts_with(prefix) && path_part.ends_with(suffix) {
                return true;
            }
        }
    }

    false
}

/// Compute the remaining glob pattern after consuming matched path components.
fn compute_remaining_glob(glob_parts: &[&str], path_parts: &[&str]) -> String {
    let mut remaining = Vec::new();
    let mut path_idx = 0;

    for glob_part in glob_parts {
        if glob_part.starts_with("**") {
            // ** and everything after it remains
            remaining.push(*glob_part);
        } else if path_idx < path_parts.len() {
            // This glob part matched a path part, consume it
            path_idx += 1;
        } else {
            // No more path parts to consume, this glob part remains
            remaining.push(*glob_part);
        }
    }

    remaining.join("/")
}

/// These patterns match all descendants of a directory.
fn root_of_unbounded_pattern(pattern: &str) -> Option<&str> {
    let mut s: &str = pattern;
    if let Some(prefix) = s.strip_suffix("/**/*") {
        s = prefix;
    }

    while let Some(prefix) = s.strip_suffix("/**") {
        s = prefix;
    }

    if s.len() == pattern.len() {
        None
    } else {
        Some(s)
    }
}

fn should_traverse_deep(patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        !pattern.starts_with('!') && (pattern.contains("**") || pattern.contains("/"))
    })
}

fn is_hidden_dot(path: &Path) -> bool {
    path.file_name()
        .and_then(|file| file.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

// Inline test module to test internal utilities, which are
// only pub(crate)
#[cfg(test)]
mod test {
    use super::GlobSet;

    #[test]
    fn root_of_unbounded_pattern() {
        assert_eq!(super::root_of_unbounded_pattern("foo/**"), Some("foo"));
        assert_eq!(
            super::root_of_unbounded_pattern("foo/bar/**"),
            Some("foo/bar")
        );
        assert_eq!(super::root_of_unbounded_pattern("foo/**/*"), Some("foo"));
        assert_eq!(
            super::root_of_unbounded_pattern("foo/bar/**/*"),
            Some("foo/bar")
        );
        assert_eq!(super::root_of_unbounded_pattern("foo/*"), None);
        assert_eq!(super::root_of_unbounded_pattern("foo/bar/*"), None);
        assert_eq!(super::root_of_unbounded_pattern("foo/**/**"), Some("foo"));
        assert_eq!(
            super::root_of_unbounded_pattern("foo/**/*/**/*"),
            Some("foo/**/*")
        );
        assert_eq!(
            super::root_of_unbounded_pattern("foo/*/*/**"),
            Some("foo/*/*")
        );
        assert_eq!(super::root_of_unbounded_pattern("foo"), None);
        assert_eq!(super::root_of_unbounded_pattern("foo/bar"), None);
        assert_eq!(super::root_of_unbounded_pattern("*.js"), None);
        assert_eq!(super::root_of_unbounded_pattern("foo/*.js"), None);
        assert_eq!(super::root_of_unbounded_pattern(""), None);
        assert_eq!(super::root_of_unbounded_pattern("/**"), Some(""));
        assert_eq!(super::root_of_unbounded_pattern("/**/*"), Some(""));
        assert_eq!(super::root_of_unbounded_pattern("/*"), None);
    }

    #[test]
    fn skips_dir_with_unbounded_negation() {
        let set = GlobSet::new(["**/*", "!node_modulez/**"]).unwrap();

        assert!(!set.should_traverse_dir("node_modulez"));
        assert!(set.should_traverse_dir("src"));
        assert!(set.should_traverse_dir("lib"));
    }

    #[test]
    fn skips_dir_with_multiple_unbounded_negations() {
        let set = GlobSet::new(["**/*", "!node_modulez/**", "!vendor/**", "!.cache/**"]).unwrap();

        assert!(!set.should_traverse_dir("node_modulez"));
        assert!(!set.should_traverse_dir("vendor"));
        assert!(!set.should_traverse_dir(".cache"));
        assert!(set.should_traverse_dir("src"));
    }

    #[test]
    fn does_not_skip_with_non_unbounded_negation() {
        let set = GlobSet::new(["**/*", "!*.log"]).unwrap();

        assert!(set.should_traverse_dir("logs"));
        assert!(set.should_traverse_dir("temp"));
    }

    #[test]
    fn skips_nested_path() {
        let set = GlobSet::new(["**/*", "!packages/*/node_modulez/**"]).unwrap();

        assert!(!set.should_traverse_dir("packages/app/node_modulez"));
        assert!(set.should_traverse_dir("node_modulez"));
        assert!(set.should_traverse_dir("packages/app"));
    }

    #[test]
    fn handles_globstar_star_suffix() {
        let set = GlobSet::new(["**/*", "!build/**/*"]).unwrap();

        assert!(set.should_traverse_dir("src"));
        assert!(!set.should_traverse_dir("build"));
    }

    #[test]
    fn empty_set_does_not_skip() {
        let set = GlobSet::new(["**/*"]).unwrap();

        assert!(set.should_traverse_dir("any_dir"));
        assert!(set.should_traverse_dir("node_modulez"));
    }

    #[test]
    fn using_split_constructor() {
        let set = GlobSet::new_split(["**/*"], ["node_modulez/**", "dist/**"]).unwrap();

        assert!(!set.should_traverse_dir("node_modulez"));
        assert!(!set.should_traverse_dir("dist"));
        assert!(set.should_traverse_dir("src"));
    }
}
