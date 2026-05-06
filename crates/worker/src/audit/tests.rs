/// **Invariant pin (v0.50.2, RFC 008)** — no `audit::write_*` call site
/// shall pass token material through any field, including `reason`.
///
/// The denylist covers substrings that strongly indicate secret material
/// appearing in a format string argument to an audit write call.
///
/// If a future contributor hits this test legitimately (e.g., a new key
/// name that happens to match the denylist), rename the field to a
/// non-secret-shaped name rather than weakening or bypassing this test.
#[test]
fn no_audit_reason_format_string_contains_secret_substring() {
    use std::fs;
    use std::path::{Path, PathBuf};

    // Substrings that indicate token material in an audit reason.
    let denylist: &[&str] = &[
        "code=",        // OTP plaintext e.g. code=ABCD1234
        "code_plaintext", // direct field reference
        "otp=",
        "secret=",
        "password=",
        "plaintext",
    ];

    // Walk all .rs source files under the workspace crates/ directory,
    // excluding test files (tests.rs and files under /tests/ directories).
    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // Skip test-only files — the denylist is for production
                // call sites; test fixtures may construct synthetic
                // strings to assert the pin works.
                let name = path.file_name().unwrap().to_string_lossy();
                let in_test_dir = path
                    .components()
                    .any(|c| c.as_os_str() == "tests");
                if name != "tests.rs" && !in_test_dir {
                    out.push(path);
                }
            }
        }
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Walk from the workspace crates/ root, not just this crate.
    let crates_dir = Path::new(manifest_dir)
        .parent() // src/
        .and_then(|p| p.parent()) // crates/worker/
        .and_then(|p| p.parent()) // crates/
        .and_then(|p| p.parent()) // workspace root
        .map(|p| p.join("crates"))
        .unwrap_or_else(|| Path::new(manifest_dir).to_path_buf());

    let mut rs_files = Vec::new();
    collect_rs_files(&crates_dir, &mut rs_files);
    assert!(
        !rs_files.is_empty(),
        "walk found no .rs files under {crates_dir:?}; check CARGO_MANIFEST_DIR"
    );

    let mut violations: Vec<String> = Vec::new();

    for path in &rs_files {
        let Ok(contents) = fs::read_to_string(path) else { continue };
        let lines: Vec<&str> = contents.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            // Only examine lines that are part of an audit::write call.
            if !line.contains("audit::write") {
                continue;
            }
            // Scan the call site plus the next 7 lines — enough to
            // cover a multi-line format!() argument.
            let end = (line_idx + 8).min(lines.len());
            let block = lines[line_idx..end].join("\n");

            for needle in denylist {
                if block.contains(needle) {
                    let display_path = path
                        .strip_prefix(&crates_dir)
                        .unwrap_or(path)
                        .display()
                        .to_string();
                    violations.push(format!(
                        "{}:{} — `{}` in audit::write context",
                        display_path,
                        line_idx + 1,
                        needle,
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Audit secret-substring denylist matched. \
         No audit::write_* call may pass token material. \
         See RFC 008 and crates/worker/src/audit.rs module doc.\n\nViolations:\n{}",
        violations.join("\n")
    );
}
