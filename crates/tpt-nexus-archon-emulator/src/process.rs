//! Processes: the framing tpt-archon does not provide.
//!
//! `tpt_archon_kernel::scheduler::Scheduler` deliberately owns its tasks and
//! exposes no lookup, no kill, and no per-task state — it is a fair round-robin
//! poller, nothing more. `tpt_archon_bridge::capability::Capability` is a pure
//! bearer token with no notion of who holds it. Neither gap is an oversight;
//! they are simply below the abstraction level of "a loaded program with an
//! identity and a capability set".
//!
//! This module supplies exactly that missing layer, and nothing else: a process
//! table keyed by the scheduler's own task id, a per-process capability set,
//! and a termination flag the task can observe. All enforcement still happens
//! inside tpt-archon.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use tpt_archon_bridge::capability::{Capability, Resource, Right};
use tpt_archon_kernel::scheduler::{Poll, Task};

/// A loaded process, identified by the scheduler task id that backs it.
///
/// Using the scheduler's id rather than a private counter keeps the two views
/// of a process — "a thing that can be scheduled" and "a thing that holds
/// capabilities" — from drifting apart.
pub type ProcessId = u64;

/// One capability, plus the reason nexus minted it.
///
/// `Capability`'s own `Debug` redacts its serial and it carries no provenance,
/// so without this record there would be no way to explain *why* a process can
/// touch a given page — which is most of what Example 2 is trying to show.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The verified function this grant was derived from.
    pub func_name: String,
    /// The page backing that function's state.
    pub block_id: u64,
    /// The right granted.
    pub right: Right,
    /// The unforgeable token itself.
    pub capability: Capability,
}

impl Grant {
    /// Whether this grant authorizes reading.
    pub fn allows_read(&self) -> bool {
        self.right.allows_read()
    }

    /// Whether this grant authorizes writing.
    pub fn allows_write(&self) -> bool {
        self.right.allows_write()
    }
}

/// A process loaded from a [`VerifiedArtifact`](tpt_nexus_orchestrator::VerifiedArtifact).
#[derive(Debug)]
pub struct Process {
    /// The scheduler task id.
    pub pid: ProcessId,
    /// A human label, taken from the artifact's first module.
    pub name: String,
    /// Size of the compiled artifact, in bytes. Zero for a headless build.
    pub image_size: usize,
    /// The `sha256:` source hash the manifest attested.
    pub source_hash: String,
    /// Capability grants, ordered by page.
    pub grants: Vec<Grant>,
    /// Set when the process is terminated; observed by its scheduler task.
    terminated: Rc<Cell<bool>>,
}

impl Process {
    pub(crate) fn new(
        pid: ProcessId,
        name: String,
        image_size: usize,
        source_hash: String,
        grants: Vec<Grant>,
        terminated: Rc<Cell<bool>>,
    ) -> Self {
        Self {
            pid,
            name,
            image_size,
            source_hash,
            grants,
            terminated,
        }
    }

    /// The grant covering `block_id`, if the process holds one.
    pub fn grant_for(&self, block_id: u64) -> Option<&Grant> {
        self.grants.iter().find(|g| g.block_id == block_id)
    }

    /// The grant derived from a named function.
    pub fn grant_for_function(&self, func_name: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.func_name == func_name)
    }

    /// The page assigned to a named function.
    pub fn page_of(&self, func_name: &str) -> Option<u64> {
        self.grant_for_function(func_name).map(|g| g.block_id)
    }

    /// Every page this process can reach, with its right.
    pub fn page_map(&self) -> BTreeMap<u64, Right> {
        self.grants.iter().map(|g| (g.block_id, g.right)).collect()
    }

    /// Whether the process has been asked to exit.
    pub fn is_terminated(&self) -> bool {
        self.terminated.get()
    }

    pub(crate) fn terminate(&self) {
        self.terminated.set(true);
    }
}

/// The scheduler task that represents a loaded artifact.
///
/// The kernel's `Scheduler` has no despawn API: a task leaves only by returning
/// `Poll::Ready`. So termination is modelled the same way
/// `out-archon-pgwire`'s connection task models a closed socket — a flag the
/// task checks on each poll.
pub(crate) struct ArtifactTask {
    pub(crate) name: String,
    pub(crate) terminated: Rc<Cell<bool>>,
    pub(crate) polls: Rc<Cell<usize>>,
}

impl Task for ArtifactTask {
    fn poll(&mut self) -> Poll {
        if self.terminated.get() {
            tracing::debug!(process = %self.name, "process task exiting");
            return Poll::Ready;
        }
        self.polls.set(self.polls.get() + 1);
        Poll::Pending
    }
}

/// The resource a grant covers, for reporting.
///
/// tpt-archon models only [`Resource::Page`] and [`Resource::Channel`]; nexus
/// currently mints pages only, but the helper keeps call sites honest about
/// which variant they mean.
pub(crate) fn page_resource(block_id: u64) -> Resource {
    Resource::Page(block_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tpt_archon_bridge::capability::CapabilityIssuer;

    fn grant(func: &str, block_id: u64, right: Right) -> Grant {
        let issuer = Rc::new(RefCell::new(CapabilityIssuer::new()));
        let capability = issuer.borrow_mut().mint(Resource::Page(block_id), right);
        Grant {
            func_name: func.to_string(),
            block_id,
            right,
            capability,
        }
    }

    fn process(grants: Vec<Grant>) -> Process {
        Process::new(
            7,
            "Demo".to_string(),
            0,
            "sha256:abc".to_string(),
            grants,
            Rc::new(Cell::new(false)),
        )
    }

    #[test]
    fn grants_are_addressable_by_page_and_by_function() {
        let p = process(vec![
            grant("read_only", 0, Right::Read),
            grant("mutator", 1, Right::ReadWrite),
        ]);
        assert_eq!(p.grant_for(0).unwrap().func_name, "read_only");
        assert_eq!(p.grant_for_function("mutator").unwrap().block_id, 1);
        assert_eq!(p.page_of("mutator"), Some(1));
        assert!(p.grant_for(99).is_none());
        assert!(p.grant_for_function("nope").is_none());
    }

    #[test]
    fn read_only_grant_does_not_allow_writing() {
        let g = grant("query", 0, Right::Read);
        assert!(g.allows_read());
        assert!(!g.allows_write());
    }

    #[test]
    fn read_write_grant_allows_both() {
        let g = grant("mutate", 0, Right::ReadWrite);
        assert!(g.allows_read());
        assert!(g.allows_write());
    }

    #[test]
    fn page_map_summarizes_reachable_pages() {
        let p = process(vec![
            grant("a", 0, Right::Read),
            grant("b", 1, Right::ReadWrite),
        ]);
        let map = p.page_map();
        assert_eq!(map.get(&0), Some(&Right::Read));
        assert_eq!(map.get(&1), Some(&Right::ReadWrite));
    }

    #[test]
    fn task_runs_until_terminated() {
        let terminated = Rc::new(Cell::new(false));
        let polls = Rc::new(Cell::new(0));
        let mut task = ArtifactTask {
            name: "Demo".to_string(),
            terminated: terminated.clone(),
            polls: polls.clone(),
        };
        assert_eq!(task.poll(), Poll::Pending);
        assert_eq!(task.poll(), Poll::Pending);
        assert_eq!(polls.get(), 2);

        terminated.set(true);
        assert_eq!(task.poll(), Poll::Ready);
        assert_eq!(polls.get(), 2, "a terminated task does no more work");
    }
}
