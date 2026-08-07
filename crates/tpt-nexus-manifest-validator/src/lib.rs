//! [5. VALIDATE] — independent re-checking of a `telos-proof.json` attestation.
//!
//! # Scope: a wrapper, deliberately
//!
//! spec.txt §4.3 describes this component as a utility that "recomputes the
//! SHA-256 hash of the associated `.telos` source file and ensures they match".
//! That logic already exists, complete and tested, as
//! [`tpt_telos_codegen::proof::verify_manifest`] — and it does *more* than the
//! spec asks, because it also re-derives the manifest's own `manifest_hash` and
//! so detects edits to the manifest JSON itself, not just to the source.
//!
//! Reimplementing hashing here would create a second, drifting definition of
//! "valid" and weaken the very property it is supposed to check. So this crate
//! is a thin, honest wrapper that adds only what a *validator* needs and the
//! library function does not provide:
//!
//! * file I/O with errors that say which path failed and why;
//! * the two failure modes kept distinct and separately reportable — a
//!   **source-hash mismatch** (the code changed after it was verified) is a
//!   different accusation from **manifest tampering** (someone edited the
//!   attestation to cover for it);
//! * a typed `Err` and a non-zero process exit when either holds.
//!
//! # Why both failure modes matter
//!
//! An attacker who edits the `.telos` source invalidates `source_hash`. An
//! attacker who then edits `source_hash` in the manifest to match invalidates
//! `manifest_hash`, because that hash is computed over the whole document.
//! Reporting only "invalid" would lose the distinction; reporting only the
//! first would let the second hide behind it.
//!
//! ```no_run
//! use std::path::Path;
//! use tpt_nexus_manifest_validator::validate_files;
//!
//! let report = validate_files(
//!     Path::new("out/telos-proof.json"),
//!     Path::new("out/source.telos"),
//! )?;
//! assert!(report.is_valid());
//! # Ok::<(), tpt_nexus_manifest_validator::ValidationError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::path::{Path, PathBuf};

use tpt_telos_codegen::proof::{verify_manifest, ManifestVerification};

/// The outcome of validating one manifest against one source file.
///
/// A restatement of [`ManifestVerification`] that is `Clone` (the upstream type
/// is `Debug`-only), carries the paths that were checked, and separates the two
/// failure modes behind named predicates.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// The manifest that was checked.
    pub manifest_path: PathBuf,
    /// The source file the manifest claims to attest.
    pub source_path: PathBuf,
    /// Whether the recomputed source hash matches the manifest's claim.
    pub source_hash_valid: bool,
    /// Whether the manifest document itself is internally consistent.
    pub manifest_hash_valid: bool,
    /// `source_hash` as recorded in the manifest.
    pub source_hash_expected: String,
    /// `source_hash` recomputed from the source file on disk.
    pub source_hash_actual: String,
    /// `manifest_hash` as recorded in the manifest.
    pub manifest_hash_expected: String,
    /// `manifest_hash` recomputed over the manifest document.
    pub manifest_hash_actual: String,
    /// True when either hash failed to reproduce.
    pub tampered: bool,
}

impl ValidationReport {
    fn from_verification(
        manifest_path: &Path,
        source_path: &Path,
        v: ManifestVerification,
    ) -> Self {
        Self {
            manifest_path: manifest_path.to_path_buf(),
            source_path: source_path.to_path_buf(),
            source_hash_valid: v.source_hash_valid,
            manifest_hash_valid: v.manifest_hash_valid,
            source_hash_expected: v.source_hash_expected,
            source_hash_actual: v.source_hash_actual,
            manifest_hash_expected: v.manifest_hash_expected,
            manifest_hash_actual: v.manifest_hash_actual,
            tampered: v.tampered,
        }
    }

    /// Whether the attestation holds and the artifact may be trusted.
    pub fn is_valid(&self) -> bool {
        !self.tampered
    }

    /// The source file changed after it was verified.
    pub fn source_was_modified(&self) -> bool {
        !self.source_hash_valid
    }

    /// The manifest document itself was edited.
    pub fn manifest_was_modified(&self) -> bool {
        !self.manifest_hash_valid
    }

    /// Convert a failing report into the corresponding typed error.
    ///
    /// Returns `Ok(())` when the attestation holds. When both hashes fail,
    /// manifest tampering is reported first: an inconsistent manifest means the
    /// `source_hash` it claims cannot be trusted as evidence of anything.
    pub fn into_result(self) -> Result<Self, ValidationError> {
        match (self.manifest_hash_valid, self.source_hash_valid) {
            (true, true) => Ok(self),
            (false, _) => Err(ValidationError::ManifestTampered {
                expected: self.manifest_hash_expected,
                actual: self.manifest_hash_actual,
            }),
            (true, false) => Err(ValidationError::SourceHashMismatch {
                expected: self.source_hash_expected,
                actual: self.source_hash_actual,
            }),
        }
    }

    /// A multi-line human-readable rendering, naming the failure mode.
    pub fn render(&self) -> String {
        let mut out = format!(
            "manifest: {}\nsource:   {}\n",
            self.manifest_path.display(),
            self.source_path.display()
        );
        out.push_str(&format!(
            "  source hash   {}\n    expected {}\n    actual   {}\n",
            if self.source_hash_valid {
                "OK"
            } else {
                "MISMATCH"
            },
            self.source_hash_expected,
            self.source_hash_actual
        ));
        out.push_str(&format!(
            "  manifest hash {}\n    expected {}\n    actual   {}\n",
            if self.manifest_hash_valid {
                "OK"
            } else {
                "MISMATCH"
            },
            self.manifest_hash_expected,
            self.manifest_hash_actual
        ));
        out.push_str(match (self.manifest_hash_valid, self.source_hash_valid) {
            (true, true) => "VALID: the source matches its attestation.",
            (false, true) => "TAMPERED: the manifest document was edited after it was generated.",
            (true, false) => "TAMPERED: the source was modified after it was verified.",
            (false, false) => {
                "TAMPERED: the source was modified and the manifest was edited to match."
            }
        });
        out
    }
}

/// Why validation could not be completed, or did not hold.
#[derive(Debug)]
pub enum ValidationError {
    /// A file could not be read.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The source no longer hashes to the value recorded in the manifest:
    /// the code changed after it was verified.
    SourceHashMismatch {
        /// Hash the manifest claims.
        expected: String,
        /// Hash the source on disk actually produces.
        actual: String,
    },
    /// The manifest document does not hash to its own recorded
    /// `manifest_hash`: the attestation itself was edited.
    ManifestTampered {
        /// Hash the manifest claims for itself.
        expected: String,
        /// Hash the document actually produces.
        actual: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Io { path, source } => {
                write!(f, "cannot read `{}`: {source}", path.display())
            }
            ValidationError::SourceHashMismatch { expected, actual } => write!(
                f,
                "source hash mismatch: the source was modified after verification\n  \
                 manifest claims {expected}\n  source hashes to {actual}"
            ),
            ValidationError::ManifestTampered { expected, actual } => write!(
                f,
                "manifest tampered: the attestation document was edited\n  \
                 manifest claims {expected}\n  document hashes to {actual}"
            ),
        }
    }
}

impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ValidationError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Validate a manifest against source bytes already in memory.
///
/// Never fails: the returned report describes what held and what did not. Use
/// [`ValidationReport::into_result`] for the typed-error form.
pub fn validate_bytes(
    manifest_path: &Path,
    source_path: &Path,
    manifest_json: &str,
    source_bytes: &[u8],
) -> ValidationReport {
    ValidationReport::from_verification(
        manifest_path,
        source_path,
        verify_manifest(manifest_json, source_bytes),
    )
}

/// Read a manifest and its source from disk and validate them.
///
/// # Errors
///
/// [`ValidationError::Io`] if either file cannot be read;
/// [`ValidationError::SourceHashMismatch`] or
/// [`ValidationError::ManifestTampered`] when the attestation does not hold.
pub fn validate_files(
    manifest_path: &Path,
    source_path: &Path,
) -> Result<ValidationReport, ValidationError> {
    let manifest_json =
        std::fs::read_to_string(manifest_path).map_err(|source| ValidationError::Io {
            path: manifest_path.to_path_buf(),
            source,
        })?;
    // Read as bytes, not text: the manifest hashes the file's bytes, so any
    // lossy decode would change the answer.
    let source_bytes = std::fs::read(source_path).map_err(|source| ValidationError::Io {
        path: source_path.to_path_buf(),
        source,
    })?;

    validate_bytes(manifest_path, source_path, &manifest_json, &source_bytes).into_result()
}

/// Read and validate, returning the report even when the attestation fails.
///
/// Only I/O errors are `Err`. Useful for tools that want to render both failure
/// modes rather than stopping at the first.
pub fn inspect_files(
    manifest_path: &Path,
    source_path: &Path,
) -> Result<ValidationReport, ValidationError> {
    let manifest_json =
        std::fs::read_to_string(manifest_path).map_err(|source| ValidationError::Io {
            path: manifest_path.to_path_buf(),
            source,
        })?;
    let source_bytes = std::fs::read(source_path).map_err(|source| ValidationError::Io {
        path: source_path.to_path_buf(),
        source,
    })?;

    Ok(validate_bytes(
        manifest_path,
        source_path,
        &manifest_json,
        &source_bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real manifest by running the actual telos pipeline, so these
    /// tests exercise the genuine hashing path rather than a hand-written JSON
    /// fixture that could drift from the format.
    fn manifest_for(source: &str) -> String {
        let modules = tpt_telos_parser::parse(source).expect("parses");
        let outcomes: Vec<_> = modules
            .iter()
            .flat_map(|m| {
                tpt_telos_agent::transpile_module(m, &tpt_telos_agent::StaticAgent::new())
                    .expect("transpiles")
            })
            .collect();
        let manifest = tpt_telos_codegen::proof::generate_manifest(source.as_bytes(), &outcomes);
        tpt_telos_codegen::proof::to_json(&manifest)
    }

    const SOURCE: &str = r#"
        module Counter {
            invariant Counter { value >= 0 }
            func increment(c: Counter, by: PositiveInt)
                requires c.value >= 0
                ensures c.value == old(c.value) + by
            ;
        }
    "#;

    fn paths() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("telos-proof.json"),
            PathBuf::from("source.telos"),
        )
    }

    #[test]
    fn untouched_attestation_validates() {
        let (m, s) = paths();
        let report = validate_bytes(&m, &s, &manifest_for(SOURCE), SOURCE.as_bytes());
        assert!(report.is_valid());
        assert!(report.source_hash_valid);
        assert!(report.manifest_hash_valid);
        assert!(!report.source_was_modified());
        assert!(!report.manifest_was_modified());
        assert!(report.render().contains("VALID"));
        assert!(report.into_result().is_ok());
    }

    #[test]
    fn modified_source_is_reported_as_a_source_mismatch() {
        let (m, s) = paths();
        let manifest = manifest_for(SOURCE);
        // The attacker edits the code after it was verified.
        let tampered_source = SOURCE.replace("+ by", "- by");

        let report = validate_bytes(&m, &s, &manifest, tampered_source.as_bytes());
        assert!(!report.is_valid());
        assert!(report.source_was_modified());
        assert!(
            !report.manifest_was_modified(),
            "the manifest document is untouched"
        );
        assert!(report.render().contains("source was modified"));

        match report.into_result() {
            Err(ValidationError::SourceHashMismatch { expected, actual }) => {
                assert_ne!(expected, actual);
                assert!(expected.starts_with("sha256:"));
            }
            other => panic!("expected SourceHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn edited_manifest_is_reported_as_tampering() {
        let (m, s) = paths();
        // The attacker edits the attestation, not the code: flip a per-function
        // `verified` flag to claim a proof that was never produced.
        let manifest = manifest_for(SOURCE).replace("\"verified\": true", "\"verified\": false");

        let report = validate_bytes(&m, &s, &manifest, SOURCE.as_bytes());
        assert!(!report.is_valid());
        assert!(report.manifest_was_modified());
        assert!(
            !report.source_was_modified(),
            "the source itself is untouched"
        );
        assert!(report.render().contains("manifest document was edited"));

        match report.into_result() {
            Err(ValidationError::ManifestTampered { expected, actual }) => {
                assert_ne!(expected, actual);
            }
            other => panic!("expected ManifestTampered, got {other:?}"),
        }
    }

    #[test]
    fn forged_source_hash_is_caught_by_the_manifest_hash() {
        // The interesting attack: change the code, then rewrite `source_hash`
        // in the manifest so it matches. The document-level hash catches it.
        let (m, s) = paths();
        let tampered_source = SOURCE.replace("+ by", "- by");

        let honest = manifest_for(SOURCE);
        let forged_hash = {
            let real = manifest_for(&tampered_source);
            extract(&real, "source_hash")
        };
        let manifest = honest.replace(&extract(&honest, "source_hash"), &forged_hash);

        let report = validate_bytes(&m, &s, &manifest, tampered_source.as_bytes());
        assert!(
            report.source_hash_valid,
            "the forged source_hash does match the modified source"
        );
        assert!(
            report.manifest_was_modified(),
            "but the document no longer hashes to its own manifest_hash"
        );
        assert!(!report.is_valid());
        assert!(matches!(
            report.into_result(),
            Err(ValidationError::ManifestTampered { .. })
        ));
    }

    /// Pull a `"key": "value"` string out of the hand-rolled manifest JSON.
    fn extract(json: &str, key: &str) -> String {
        let needle = format!("\"{key}\": \"");
        let start = json.find(&needle).expect("key present") + needle.len();
        let end = start + json[start..].find('"').expect("closing quote");
        json[start..end].to_string()
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let err = validate_files(
            Path::new("does-not-exist-telos-proof.json"),
            Path::new("does-not-exist.telos"),
        )
        .expect_err("missing files cannot validate");
        assert!(matches!(err, ValidationError::Io { .. }), "got {err:?}");
        assert!(err.to_string().contains("does-not-exist"));
    }

    #[test]
    fn round_trip_through_disk_validates() {
        let dir = std::env::temp_dir().join(format!(
            "nexus-validator-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("telos-proof.json");
        let source_path = dir.join("source.telos");
        std::fs::write(&manifest_path, manifest_for(SOURCE)).unwrap();
        std::fs::write(&source_path, SOURCE).unwrap();

        let report = validate_files(&manifest_path, &source_path).expect("valid attestation");
        assert!(report.is_valid());
        assert_eq!(report.manifest_path, manifest_path);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inspect_returns_a_report_even_when_invalid() {
        let dir = std::env::temp_dir().join(format!(
            "nexus-validator-inspect-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("telos-proof.json");
        let source_path = dir.join("source.telos");
        std::fs::write(&manifest_path, manifest_for(SOURCE)).unwrap();
        std::fs::write(&source_path, SOURCE.replace("+ by", "- by")).unwrap();

        let report = inspect_files(&manifest_path, &source_path).expect("files readable");
        assert!(!report.is_valid());
        assert!(report.source_was_modified());

        std::fs::remove_dir_all(&dir).ok();
    }
}
