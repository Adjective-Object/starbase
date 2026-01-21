use starbase_utils::glob::*;

mod globset {
    use super::*;

    #[test]
    fn doesnt_match_when_empty() {
        let list: Vec<String> = vec![];
        let set = GlobSet::new(&list).unwrap();

        assert!(!set.matches("file.ts"));

        // Testing types
        let list: Vec<&str> = vec![];
        let set = GlobSet::new(list).unwrap();

        assert!(!set.matches("file.ts"));
    }

    #[test]
    fn matches_explicit() {
        let set = GlobSet::new(["source"]).unwrap();

        assert!(set.matches("source"));
        assert!(!set.matches("source.ts"));
    }

    #[test]
    fn matches_exprs() {
        let set = GlobSet::new(["files/*.ts"]).unwrap();

        assert!(set.matches("files/index.ts"));
        assert!(set.matches("files/test.ts"));
        assert!(!set.matches("index.ts"));
        assert!(!set.matches("files/index.js"));
        assert!(!set.matches("files/dir/index.ts"));
    }

    #[test]
    fn matches_rel_start() {
        let set = GlobSet::new(["./source"]).unwrap();

        assert!(set.matches("source"));
        assert!(!set.matches("source.ts"));
    }

    #[test]
    fn doesnt_match_negations() {
        let set = GlobSet::new(["files/*", "!**/*.ts"]).unwrap();

        assert!(set.matches("files/test.js"));
        assert!(set.matches("files/test.go"));
        assert!(!set.matches("files/test.ts"));
    }

    #[test]
    fn doesnt_match_negations_using_split() {
        let set = GlobSet::new_split(["files/*"], ["**/*.ts"]).unwrap();

        assert!(set.matches("files/test.js"));
        assert!(set.matches("files/test.go"));
        assert!(!set.matches("files/test.ts"));
    }

    #[test]
    fn doesnt_match_global_negations() {
        let set = GlobSet::new(["files/**/*"]).unwrap();

        assert!(set.matches("files/test.js"));
        assert!(!set.matches("files/node_modules/test.js"));
        assert!(!set.matches("files/.git/cache"));
    }
}

mod is_glob {
    use super::*;

    #[test]
    fn returns_true_when_a_glob() {
        assert!(is_glob("**"));
        assert!(is_glob("**/src/*"));
        assert!(is_glob("src/**"));
        assert!(is_glob("*.ts"));
        assert!(is_glob("file.*"));
        assert!(is_glob("file.{js,ts}"));
        assert!(is_glob("file.[jstx]"));
        assert!(is_glob("file.tsx?"));
    }

    #[test]
    fn returns_false_when_not_glob() {
        assert!(!is_glob("dir"));
        assert!(!is_glob("file.rs"));
        assert!(!is_glob("dir/file.ts"));
        assert!(!is_glob("dir/dir/file_test.rs"));
        assert!(!is_glob("dir/dirDir/file-ts.js"));
    }

    #[test]
    fn returns_false_when_escaped_glob() {
        assert!(!is_glob("\\*.rs"));
        assert!(!is_glob("file\\?.js"));
        assert!(!is_glob("folder-\\[id\\]"));
    }
}

mod split_patterns {
    use super::*;

    #[test]
    fn splits_all_patterns() {
        assert_eq!(
            split_patterns(["*.file", "!neg1.*", "/*.file2", "/!neg2.*", "!/neg3.*"]),
            (
                vec!["*.file", "*.file2"],
                vec!["neg1.*", "neg2.*", "neg3.*"]
            )
        );
    }
}

mod walk {
    use super::*;

    #[test]
    fn fast_and_slow_return_same_list() {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        let slow = walk(&dir, ["**/*"]).unwrap();
        let fast = walk_fast(&dir, ["**/*"]).unwrap();

        assert_eq!(slow.len(), fast.len());

        let slow = walk(&dir, ["**/*.snap"]).unwrap();
        let fast = walk_fast(&dir, ["**/*.snap"]).unwrap();

        assert_eq!(slow.len(), fast.len());
    }
}

mod walk_files {
    use super::*;

    #[test]
    fn fast_and_slow_return_same_list() {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        let slow = walk_files(&dir, ["**/*"]).unwrap();
        let fast = walk_fast_with_options(
            &dir,
            ["**/*"],
            GlobWalkOptions {
                only_files: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(slow.len(), fast.len());

        let slow = walk_files(&dir, ["**/*.snap"]).unwrap();
        let fast = walk_fast_with_options(
            &dir,
            ["**/*.snap"],
            GlobWalkOptions {
                only_files: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(slow.len(), fast.len());
    }
}

mod walk_fast {
    use super::*;
    use starbase_sandbox::create_empty_sandbox;

    #[test]
    fn handles_dot_folders() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("1.txt", "");
        sandbox.create_file("dir/2.txt", "");
        sandbox.create_file(".hidden/3.txt", "");

        let mut paths =
            walk_fast_with_options(sandbox.path(), ["**/*.txt"], GlobWalkOptions::default())
                .unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join("1.txt"),
                sandbox.path().join("dir/2.txt"),
            ]
        );

        let mut paths = walk_fast_with_options(
            sandbox.path(),
            ["**/*.txt"],
            GlobWalkOptions::default().dot_dirs(false).dot_files(false),
        )
        .unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join(".hidden/3.txt"),
                sandbox.path().join("1.txt"),
                sandbox.path().join("dir/2.txt"),
            ]
        );
    }

    #[test]
    fn skips_unbounded_negation_subtrees() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("src/index.ts", "");
        sandbox.create_file("src/utils.ts", "");
        sandbox.create_file("node_modules/pkg/index.js", "");
        sandbox.create_file("node_modules/pkg/lib/utils.js", "");
        sandbox.create_file("dist/output.js", "");

        let mut paths =
            walk_fast(sandbox.path(), ["**/*.ts", "**/*.js", "!node_modules/**"]).unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join("dist/output.js"),
                sandbox.path().join("src/index.ts"),
                sandbox.path().join("src/utils.ts"),
            ]
        );
    }

    #[test]
    fn skips_multiple_unbounded_negation_subtrees() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("src/index.ts", "");
        sandbox.create_file("node_modules/pkg/index.js", "");
        sandbox.create_file("vendor/lib/utils.js", "");
        sandbox.create_file("build/output.js", "");

        let mut paths = walk_fast(
            sandbox.path(),
            ["**/*", "!node_modules/**", "!vendor/**", "!build/**"],
        )
        .unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join("src"),
                sandbox.path().join("src/index.ts"),
            ]
        );
    }

    #[test]
    fn skips_deeply_nested_unbounded_negations() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("a/b/c/keep.txt", "");
        sandbox.create_file("a/b/skip/file.txt", "");
        sandbox.create_file("a/b/skip/deep/nested.txt", "");

        let mut paths = walk_fast(sandbox.path(), ["**/*.txt", "!a/b/skip/**"]).unwrap();
        paths.sort();

        assert_eq!(paths, vec![sandbox.path().join("a/b/c/keep.txt"),]);
    }

    #[test]
    fn unbounded_negation_with_globstar_suffix() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("src/index.ts", "");
        sandbox.create_file("cache/data.bin", "");
        sandbox.create_file("cache/sub/more.bin", "");

        // Test with **/* suffix
        let mut paths = walk_fast(sandbox.path(), ["**/*", "!cache/**/*"]).unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join("cache"),
                sandbox.path().join("src"),
                sandbox.path().join("src/index.ts"),
            ]
        );
    }

    #[test]
    fn non_unbounded_negation_does_not_skip_subtree() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("logs/app.log", "");
        sandbox.create_file("logs/debug.log", "");
        sandbox.create_file("logs/archive/old.log", "");

        // Non-unbounded negation should not skip the entire subtree
        let mut paths = walk_fast(sandbox.path(), ["**/*.log", "!logs/*.log"]).unwrap();
        paths.sort();

        // Only files directly in logs/ are excluded, nested files are still included
        assert_eq!(paths, vec![sandbox.path().join("logs/archive/old.log"),]);
    }

    #[test]
    fn combines_unbounded_and_non_unbounded_negations() {
        let sandbox = create_empty_sandbox();
        sandbox.create_file("src/index.ts", "");
        sandbox.create_file("src/test.spec.ts", "");
        sandbox.create_file("node_modules/pkg/index.js", "");
        sandbox.create_file("dist/output.js", "");

        let mut paths = walk_fast(
            sandbox.path(),
            ["**/*.ts", "**/*.js", "!node_modules/**", "!**/*.spec.ts"],
        )
        .unwrap();
        paths.sort();

        assert_eq!(
            paths,
            vec![
                sandbox.path().join("dist/output.js"),
                sandbox.path().join("src/index.ts"),
            ]
        );
    }
}

mod partition_patterns {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn basic() {
        let map = partition_patterns("/root", ["foo/*", "foo/bar/*.txt", "baz/**/*"]);

        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root/foo".into(), vec!["*".into(), "bar/*.txt".into()]),
                ("/root/baz".into(), vec!["**/*".into()]),
            ])
        );
    }

    #[test]
    fn no_globs() {
        let map = partition_patterns("/root", ["foo/file.txt", "foo/bar/file.txt", "file.txt"]);

        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root".into(), vec!["file.txt".into()]),
                (
                    "/root/foo".into(),
                    vec!["file.txt".into(), "bar/file.txt".into()]
                ),
            ])
        );
    }

    #[test]
    fn same_root_dir() {
        let map = partition_patterns("/root", ["file.txt", "file.*", "*.{md,mdx}"]);

        assert_eq!(
            map,
            BTreeMap::from_iter([(
                "/root".into(),
                vec!["file.*".into(), "file.txt".into(), "*.{md,mdx}".into()]
            ),])
        );
    }

    #[test]
    fn same_nested_dir() {
        let map = partition_patterns(
            "/root",
            ["nes/ted/file.txt", "nes/ted/file.*", "nes/ted/*.{md,mdx}"],
        );

        assert_eq!(
            map,
            BTreeMap::from_iter([(
                "/root/nes/ted".into(),
                vec!["file.*".into(), "file.txt".into(), "*.{md,mdx}".into()]
            ),])
        );
    }

    #[test]
    fn dot_dir() {
        let map = partition_patterns("/root", [".dir/**/*.yml"]);

        assert_eq!(
            map,
            BTreeMap::from_iter([("/root/.dir".into(), vec!["**/*.yml".into()]),])
        );
    }

    #[test]
    fn with_negations() {
        let map = partition_patterns(
            "/root",
            [
                "./packages/*",
                "!packages/cli",
                "!packages/core-*",
                "website",
            ],
        );

        // Negations for packages/* go to the packages partition.
        // They also appear in root because packages is a child of root,
        // and root's pattern could match paths in packages.
        assert_eq!(
            map,
            BTreeMap::from_iter([
                (
                    "/root".into(),
                    vec![
                        "website".into(),
                        "!packages/cli".into(),
                        "!packages/core-*".into()
                    ]
                ),
                (
                    "/root/packages".into(),
                    vec!["*".into(), "!cli".into(), "!core-*".into()]
                ),
            ])
        );
    }

    #[test]
    fn global_negations() {
        let map = partition_patterns(
            "/root",
            [
                "foo/file.txt",
                "foo/bar/file.txt",
                "file.txt",
                "!**/node_modules/**",
            ],
        );

        assert_eq!(
            map,
            BTreeMap::from_iter([
                (
                    "/root".into(),
                    vec!["file.txt".into(), "!**/node_modules/**".into(),]
                ),
                (
                    "/root/foo".into(),
                    vec![
                        "file.txt".into(),
                        "bar/file.txt".into(),
                        "!**/node_modules/**".into(),
                    ]
                ),
            ])
        );
    }

    #[test]
    fn glob_stars() {
        let map = partition_patterns("/root", ["**/file.txt", "dir/sub/**/*", "other/**/*.txt"]);

        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root".into(), vec!["**/file.txt".into()]),
                ("/root/dir/sub".into(), vec!["**/*".into()]),
                ("/root/other".into(), vec!["**/*.txt".into()]),
            ])
        );
    }

    // Negation partitioning tests:
    // Negations should be included in partitions where they could potentially match files,
    // and dropped when they don't overlap with any partition.

    #[test]
    fn negation_included_in_overlapping_partitions() {
        // Negation as child of partition: !build/** included in root's **/*
        assert_eq!(
            partition_patterns("/root", ["**/*", "!build/**"]),
            BTreeMap::from_iter([("/root".into(), vec!["**/*".into(), "!build/**".into()])])
        );

        // Nested negation: !src/tests/** included in src/** as !tests/**
        assert_eq!(
            partition_patterns("/root", ["src/**", "!src/tests/**"]),
            BTreeMap::from_iter([("/root/src".into(), vec!["**".into(), "!tests/**".into()])])
        );

        // Global negation applies to child partition
        assert_eq!(
            partition_patterns("/root", ["build/**", "!**"]),
            BTreeMap::from_iter([("/root/build".into(), vec!["**".into(), "!**".into()])])
        );
    }

    #[test]
    fn negation_dropped_when_no_overlap() {
        // Sibling directories: !build_types/** doesn't affect build/**
        assert_eq!(
            partition_patterns("/root", ["build/**", "!build_types/**"]),
            BTreeMap::from_iter([("/root/build".into(), vec!["**".into()])])
        );

        // Unrelated directories: !vendor/** doesn't affect build/**/*
        assert_eq!(
            partition_patterns("/root", ["build/**/*", "!vendor/**"]),
            BTreeMap::from_iter([("/root/build".into(), vec!["**/*".into()])])
        );

        // !node_modules/** only goes to root, not to packages (different subtrees)
        assert_eq!(
            partition_patterns("/root", ["**/*", "packages/**", "!node_modules/**"]),
            BTreeMap::from_iter([
                (
                    "/root".into(),
                    vec!["**/*".into(), "!node_modules/**".into()]
                ),
                ("/root/packages".into(), vec!["**".into()]),
            ])
        );
    }

    #[test]
    fn multiple_negations_distributed_correctly() {
        // !src/generated/** goes to both root (as src/generated/**) and src (as generated/**)
        // !node_modules/** and !dist/** only go to root since they're direct children of root
        let map = partition_patterns(
            "/root",
            [
                "**/*",
                "src/**",
                "!node_modules/**",
                "!src/generated/**",
                "!dist/**",
            ],
        );

        assert_eq!(
            map,
            BTreeMap::from_iter([
                (
                    "/root".into(),
                    vec![
                        "**/*".into(),
                        "!dist/**".into(),
                        "!node_modules/**".into(),
                        "!src/generated/**".into()
                    ]
                ),
                (
                    "/root/src".into(),
                    vec!["**".into(), "!generated/**".into()]
                ),
            ])
        );
    }

    #[test]
    fn glob_in_path_prefix() {
        // When a pattern has a glob in the path prefix, it can't be partitioned
        // into a subdirectory and stays at root.

        // foo*/bar/*.ts has glob in first component, stays at root
        // foo/index*.ts has static prefix, goes to /root/foo
        let map = partition_patterns("/root", ["foo*/bar/*.ts", "foo/index*.ts"]);
        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root".into(), vec!["foo*/bar/*.ts".into()]),
                ("/root/foo".into(), vec!["index*.ts".into()]),
            ])
        );

        // packages/*/src/**/*.ts - glob in path, can only extract "packages"
        let map = partition_patterns("/root", ["packages/*/src/**/*.ts"]);
        assert_eq!(
            map,
            BTreeMap::from_iter([("/root/packages".into(), vec!["*/src/**/*.ts".into()])])
        );
    }

    #[test]
    fn negation_with_glob_prefix_overlap() {
        // Negation with glob in prefix: !foo*/** could match foo/, foo-bar/, etc.
        // It should appear in BOTH root (full pattern) AND in partitions it could match.

        // !foo*/** has a glob prefix that could match "foo"
        // So it goes to root as !foo*/** AND to /root/foo/bar as !** (since foo* matches foo)
        let map = partition_patterns("/root", ["**/*", "foo/bar/**", "!foo*/**"]);
        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root".into(), vec!["**/*".into(), "!foo*/**".into()]),
                // foo/bar partition DOES get !** because foo* could match "foo"
                ("/root/foo/bar".into(), vec!["**".into(), "!**".into()]),
            ])
        );

        // More specific: !pkg-*/** should match pkg-foo/, pkg-bar/, but not pkg/
        let map = partition_patterns("/root", ["**/*", "pkg/src/**", "!pkg-*/**"]);
        assert_eq!(
            map,
            BTreeMap::from_iter([
                ("/root".into(), vec!["**/*".into(), "!pkg-*/**".into()]),
                // pkg/src doesn't match pkg-*, so no negation here
                ("/root/pkg/src".into(), vec!["**".into()]),
            ])
        );

        // Static negation with glob in middle: !packages/*/node_modules/**
        // This can be partitioned to /root/packages with */node_modules/**
        let map = partition_patterns("/root", ["packages/**", "!packages/*/node_modules/**"]);
        assert_eq!(
            map,
            BTreeMap::from_iter([(
                "/root/packages".into(),
                vec!["**".into(), "!*/node_modules/**".into()]
            )])
        );
    }
}
