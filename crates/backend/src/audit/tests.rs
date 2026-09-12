/// Substrings that indicate token material in an audit reason.
///
/// Module-level (RFC 136 C2-136) so the invariant test and the scanner
/// self-check below share one list — a self-check against a private copy
/// would prove nothing about the list the invariant actually uses.
const DENYLIST: &[&str] = &[
    "code=",        // OTP plaintext e.g. code=ABCD1234
    "code_plaintext", // direct field reference
    "otp=",
    "secret=",
    "password=",
    "plaintext",
];

/// The source text of the call expression starting at `start` — the
/// byte offset of an `audit::write` occurrence — through the `)` that
/// balances the call's opening `(`.
///
/// RFC 136 C1-136: this replaces a fixed eight-line window. A window
/// measured in lines asserts on whatever happens to follow the call,
/// which on its first execution produced two false alarms from the
/// statement *after* the one being tested. A test about what a call
/// passes must read that call and nothing after it.
///
/// Parens inside string literals, char literals, and comments do not
/// count toward the balance. Returns `None` if the call does not close
/// before end-of-file; the caller fails loudly rather than falling
/// back to a wider window, which would re-introduce the defect with a
/// different number.
fn call_expression(src: &str, start: usize) -> Option<&str> {
    let b = src.as_bytes();
    let mut i = start;
    let mut depth = 0usize;
    let mut opened = false;

    while i < b.len() {
        match b[i] {
            // Line comment — skip to end of line.
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            // Block comment — skip to the terminator.
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            // Raw string: r"…", r#"…"#, r##"…"##  — only when `r` does
            // not continue an identifier (so `str` is not mistaken).
            b'r' if !(i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) => {
                let mut j = i + 1;
                let mut hashes = 0usize;
                while j < b.len() && b[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < b.len() && b[j] == b'"' {
                    j += 1;
                    // Find the closing quote followed by `hashes` `#`.
                    loop {
                        if j >= b.len() {
                            return None;
                        }
                        if b[j] == b'"' {
                            let mut k = j + 1;
                            let mut seen = 0usize;
                            while k < b.len() && seen < hashes && b[k] == b'#' {
                                seen += 1;
                                k += 1;
                            }
                            if seen == hashes {
                                j = k;
                                break;
                            }
                        }
                        j += 1;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            // Ordinary string literal, with escapes.
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            }
            // Char literal — distinguished from a lifetime by the
            // closing quote two or three bytes along.
            b'\'' => {
                let is_char_lit = (i + 2 < b.len() && b[i + 1] != b'\\' && b[i + 2] == b'\'')
                    || (i + 3 < b.len() && b[i + 1] == b'\\' && b[i + 3] == b'\'');
                if is_char_lit {
                    i += if b[i + 1] == b'\\' { 4 } else { 3 };
                } else {
                    i += 1; // lifetime
                }
            }
            b'(' => {
                depth += 1;
                opened = true;
                i += 1;
            }
            b')' => {
                if opened {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[start..=i]);
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// **Invariant pin (v0.50.2, RFC 008)** — no `audit::write_*` call site
/// shall pass token material through any field, including `reason`.
///
/// The denylist covers substrings that strongly indicate secret material
/// appearing in a format string argument to an audit write call.
///
/// If a future contributor hits this test legitimately (e.g., a new key
/// name that happens to match the denylist), rename the field to a
/// non-secret-shaped name rather than weakening or bypassing this test.
///
/// # This pin has a birthday
///
/// **It first executed successfully on 2026-09-12, under RFC 136.** Before
/// that it had never run: `cesauth-backend`'s test target did not compile
/// (RFC 136), and this test also looked for `crates/` two directories above
/// the repository root, so it could not have found its own inputs even if
/// it had. Written in v0.50.2, first executed in 0.83.0+.
///
/// On that first run the invariant was measured to **hold**: 413 source
/// files scanned, **zero** violations. Two sites had been flagged by an
/// earlier fixed-width scan window — `admin/console/tokens.rs` and
/// `admin/tenancy_console/forms/token_mint.rs` — and both were false
/// alarms: the window ran past the end of the `audit::write_owned(…)` call
/// into the *next* statement, where the renderer legitimately shows an
/// admin the token just minted for them. The scan below is bounded to the
/// call expression for exactly that reason. Neither site was changed; both
/// are correct.
#[test]
fn no_audit_reason_format_string_contains_secret_substring() {
    use std::fs;
    use std::path::{Path, PathBuf};

    // Substrings that indicate token material in an audit reason.
    let denylist: &[&str] = DENYLIST;

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
    // `CARGO_MANIFEST_DIR` is the crate directory — `<repo>/crates/backend`
    // — so two levels reach the repository root. RFC 136 C1-136: this used
    // four, landing two directories above the repo and finding no files at
    // all. The assertion below is what caught it, on the first run this
    // test ever had.
    let crates_dir = Path::new(manifest_dir)
        .parent() // <repo>/crates
        .and_then(|p| p.parent()) // <repo>
        .map(|p| p.join("crates"))
        .unwrap_or_else(|| Path::new(manifest_dir).to_path_buf());

    let mut rs_files = Vec::new();
    collect_rs_files(&crates_dir, &mut rs_files);
    assert!(
        !rs_files.is_empty(),
        "walk found no .rs files under {crates_dir:?}; check CARGO_MANIFEST_DIR"
    );

    let mut violations: Vec<String> = Vec::new();
    let mut unparsed: Vec<String> = Vec::new();

    for path in &rs_files {
        let Ok(contents) = fs::read_to_string(path) else { continue };

        let display_path = path
            .strip_prefix(&crates_dir)
            .unwrap_or(path)
            .display()
            .to_string();

        for (start, _) in contents.match_indices("audit::write") {
            let line_no = contents[..start].matches('\n').count() + 1;

            let Some(call) = call_expression(&contents, start) else {
                unparsed.push(format!("{display_path}:{line_no}"));
                continue;
            };

            for needle in denylist {
                if call.contains(needle) {
                    violations.push(format!(
                        "{display_path}:{line_no} — `{needle}` in audit::write call expression",
                    ));
                }
            }
        }
    }

    assert!(
        unparsed.is_empty(),
        "could not find the closing paren of an audit::write call — the scan \
         cannot assert anything about these sites, so it fails rather than \
         skipping them (RFC 136 C1-136):\n{}",
        unparsed.join("\n")
    );

    assert!(
        violations.is_empty(),
        "Audit secret-substring denylist matched. \
         No audit::write_* call may pass token material. \
         See RFC 008 and crates/backend/src/audit.rs module doc.\n\nViolations:\n{}",
        violations.join("\n")
    );
}

/// **The scanner proves itself (RFC 136 C2-136).**
///
/// The invariant test above is only as good as the scanner it runs on, and a
/// scanner that flags nothing passes a clean tree and a compromised one
/// identically. This feeds it synthetic call sites with known answers, so
/// every run demonstrates it can still fail — rather than that having been
/// checked once, by hand, in a review.
///
/// It also pins the defect that made the first version wrong: a fixed
/// eight-line window read past the end of the call into the next statement
/// and reported two false alarms. `stops_at_the_call_boundary` below is that
/// bug as a test.
#[test]
fn scanner_flags_denylisted_material_and_stops_at_the_call_boundary() {
    // 1. A denylisted token inside the call is flagged.
    let dirty = r#"audit::write_owned(&ctx.env, EventKind::X, Some(id), None, Some(format!("code={c}"))).await.ok();"#;
    let call = call_expression(dirty, 0).expect("call should parse");
    assert!(
        DENYLIST.iter().any(|n| call.contains(n)),
        "scanner failed to flag a denylisted token inside a call: {call}"
    );

    // 2. A clean call is not flagged.
    let clean = r#"audit::write_owned(&ctx.env, EventKind::X, Some(id), None, Some(format!("role={r}"))).await.ok();"#;
    let call = call_expression(clean, 0).expect("call should parse");
    assert!(
        !DENYLIST.iter().any(|n| call.contains(n)),
        "scanner flagged a clean call: {call}"
    );

    // 3. The regression that produced two false alarms: a denylisted word in
    //    the *following* statement is outside the call and must not be read.
    let next_stmt = concat!(
        "audit::write_owned(&ctx.env, EventKind::X, Some(id), None, Some(format!(\"role={r}\"))).await.ok();\n",
        "\n",
        "render::html_response(page(&principal, &minted, &plaintext))\n",
    );
    let call = call_expression(next_stmt, 0).expect("call should parse");
    assert!(
        !call.contains("plaintext"),
        "scan window ran past the call into the next statement — the RFC 136 \
         C1-136 regression: {call}"
    );

    // 4. Parens inside a string literal do not end the call early.
    let parens_in_str = r#"audit::write_owned(&ctx.env, EventKind::X, Some(id), None, Some(format!("a) b (c code={x}"))).await.ok();"#;
    let call = call_expression(parens_in_str, 0).expect("call should parse");
    assert!(
        call.contains("code="),
        "a `)` inside a string literal truncated the call, hiding material \
         that follows it: {call}"
    );

    // 5. An unbalanced call yields None, so the caller fails by name rather
    //    than silently skipping the site.
    let unbalanced = r#"audit::write_owned(&ctx.env, EventKind::X, Some(id)"#;
    assert!(
        call_expression(unbalanced, 0).is_none(),
        "an unclosed call must not parse — the invariant test reports these \
         as `unparsed` rather than passing over them"
    );
}
