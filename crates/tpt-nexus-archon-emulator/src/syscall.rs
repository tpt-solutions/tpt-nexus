//! The emulated syscall interface.
//!
//! These types are genuinely nexus's own: nothing upstream has this shape.
//! tpt-archon exposes capability-checked *borrows* (`map_read` returns
//! `&Page`), which is the right primitive for in-process code but cannot cross
//! a process boundary — a syscall returns a value, not a borrow of kernel
//! memory.
//!
//! The set is kept to the minimum Examples 1 and 2 need. Every additional
//! syscall is another enforcement point to get right, and the point of the
//! harness is to prove the boundary holds, not to grow an OS.

/// A request from emulated user-space code into the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallRequest {
    /// Read a page the caller holds a read capability for.
    ReadPage {
        /// Page to read.
        block_id: u64,
    },
    /// Overwrite the start of a page the caller holds a write capability for.
    WritePage {
        /// Page to write.
        block_id: u64,
        /// Bytes to copy into the front of the page.
        data: Vec<u8>,
    },
}

impl SyscallRequest {
    /// The page this request targets.
    pub fn block_id(&self) -> u64 {
        match self {
            SyscallRequest::ReadPage { block_id } | SyscallRequest::WritePage { block_id, .. } => {
                *block_id
            }
        }
    }

    /// The syscall name, for logs.
    pub fn name(&self) -> &'static str {
        match self {
            SyscallRequest::ReadPage { .. } => "read_page",
            SyscallRequest::WritePage { .. } => "write_page",
        }
    }
}

/// The kernel's reply to a permitted syscall.
///
/// `Page` carries owned bytes rather than a [`MemoryView`]. That is not a
/// weakening of the zero-copy claim, it is where the claim stops applying: the
/// grant layer really does hand out an in-place borrow of the page frame, and
/// the emulator really does use it, but a syscall *return value* has to cross
/// the emulated address-space boundary and therefore has to be a copy.
///
/// For the zero-copy path, use
/// [`ArchonEmulator::with_page`](crate::ArchonEmulator::with_page), which
/// exposes the borrowed `MemoryView` directly and never materializes a `Vec`.
///
/// [`MemoryView`]: tpt_archon_bridge::grant::MemoryView
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallResponse {
    /// Contents of the requested page.
    Page {
        /// Page that was read.
        block_id: u64,
        /// A copy of the page's bytes.
        bytes: Vec<u8>,
    },
    /// Bytes written.
    Written {
        /// Page that was written.
        block_id: u64,
        /// Bytes copied into the page.
        len: usize,
    },
}

impl SyscallResponse {
    /// The page bytes, if this is a read response.
    pub fn as_page(&self) -> Option<&[u8]> {
        match self {
            SyscallResponse::Page { bytes, .. } => Some(bytes),
            SyscallResponse::Written { .. } => None,
        }
    }

    /// The number of bytes written, if this is a write response.
    pub fn written_len(&self) -> Option<usize> {
        match self {
            SyscallResponse::Written { len, .. } => Some(*len),
            SyscallResponse::Page { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_report_their_target_and_name() {
        let read = SyscallRequest::ReadPage { block_id: 3 };
        assert_eq!(read.block_id(), 3);
        assert_eq!(read.name(), "read_page");

        let write = SyscallRequest::WritePage {
            block_id: 4,
            data: vec![1, 2, 3],
        };
        assert_eq!(write.block_id(), 4);
        assert_eq!(write.name(), "write_page");
    }

    #[test]
    fn responses_project_to_the_right_payload() {
        let page = SyscallResponse::Page {
            block_id: 0,
            bytes: vec![9],
        };
        assert_eq!(page.as_page(), Some(&[9u8][..]));
        assert_eq!(page.written_len(), None);

        let written = SyscallResponse::Written {
            block_id: 0,
            len: 2,
        };
        assert_eq!(written.written_len(), Some(2));
        assert_eq!(written.as_page(), None);
    }
}
