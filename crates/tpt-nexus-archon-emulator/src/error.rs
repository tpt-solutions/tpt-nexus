//! Errors raised by the Archon emulator's process and syscall layer.

use std::fmt;

use tpt_archon_bridge::capability::Right;
use tpt_archon_core::block::StorageError;

use crate::process::ProcessId;

/// Why a load or a syscall was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchonError {
    /// The process holds no capability authorizing this access.
    ///
    /// The demonstration target of Example 2: compiled code reaching for a
    /// right it was never granted is stopped at the kernel boundary, not by a
    /// check the generated code politely performs on itself.
    CapabilityViolation {
        /// The offending process.
        pid: ProcessId,
        /// The page it reached for.
        block_id: u64,
        /// The right the syscall needed.
        attempted: Right,
        /// The right the process actually holds for that page, if any.
        held: Option<Right>,
    },

    /// The page is outside the emulated device.
    OutOfBounds {
        /// The page requested.
        block_id: u64,
        /// Pages the device actually provides.
        block_count: u64,
    },

    /// No such process, or it has already terminated.
    ProcessNotFound(ProcessId),

    /// The artifact's manifest does not match its source, so no capability may
    /// be minted for it.
    ///
    /// "Manifest as Root of Trust", enforced at the point of minting rather
    /// than assumed from an upstream check.
    InvalidAttestation(String),

    /// The artifact contains at least one function that never verified.
    UnverifiedArtifact {
        /// Names of the functions that did not verify.
        functions: Vec<String>,
    },

    /// A write carried more bytes than a page holds.
    PayloadTooLarge {
        /// Bytes supplied.
        given: usize,
        /// Bytes a page can hold.
        capacity: usize,
    },

    /// The emulated storage device failed.
    Storage(StorageError),

    /// Two modules declare a function with the same name.
    ///
    /// Capability grants and `page_of` are keyed by bare function name, so a
    /// name shared across modules is ambiguous: nexus could not tell which
    /// module's `transfer` a grant belongs to, and the proof manifest has
    /// already collapsed the two into one entry. Failing loudly here is safer
    /// than silently under-granting one of them.
    AmbiguousFunctionName(String),
}

impl fmt::Display for ArchonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchonError::CapabilityViolation {
                pid,
                block_id,
                attempted,
                held,
            } => {
                write!(
                    f,
                    "capability violation: process {pid} attempted {attempted:?} on page {block_id}, "
                )?;
                match held {
                    Some(right) => write!(f, "but only holds {right:?}"),
                    None => write!(f, "but holds no capability for that page"),
                }
            }
            ArchonError::OutOfBounds {
                block_id,
                block_count,
            } => write!(
                f,
                "page {block_id} is out of bounds (device has {block_count} page(s))"
            ),
            ArchonError::ProcessNotFound(pid) => write!(f, "no such process: {pid}"),
            ArchonError::InvalidAttestation(why) => {
                write!(f, "refusing to mint capabilities: {why}")
            }
            ArchonError::UnverifiedArtifact { functions } => write!(
                f,
                "refusing to mint capabilities: {} function(s) unverified: {}",
                functions.len(),
                functions.join(", ")
            ),
            ArchonError::PayloadTooLarge { given, capacity } => write!(
                f,
                "payload of {given} byte(s) exceeds the {capacity}-byte page size"
            ),
            ArchonError::Storage(e) => write!(f, "storage error: {e}"),
            ArchonError::AmbiguousFunctionName(name) => write!(
                f,
                "function name `{name}` is declared in more than one module; \
                 capability grants are keyed by bare function name and would be ambiguous"
            ),
        }
    }
}

impl std::error::Error for ArchonError {}

impl From<StorageError> for ArchonError {
    fn from(e: StorageError) -> Self {
        ArchonError::Storage(e)
    }
}
