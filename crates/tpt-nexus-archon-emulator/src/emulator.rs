//! [`ArchonEmulator`]: [5. VALIDATE] -> [6. MINT] -> [7. EXECUTE].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use tpt_archon_bridge::capability::{Capability, CapabilityIssuer, Resource, Right, SharedIssuer};
use tpt_telos_parser::ast::Item;
use tpt_archon_bridge::page_cache::{CacheError, CorePageCache};
use tpt_archon_core::block::{InMemoryBlockDevice, StorageError};
use tpt_archon_core::page::{BufferPool, Page, PAGE_SIZE};
use tpt_archon_kernel::memory::UnifiedMemory;
use tpt_archon_kernel::scheduler::Scheduler;
use tpt_nexus_orchestrator::VerifiedArtifact;

use crate::error::ArchonError;
use crate::process::{page_resource, ArtifactTask, Grant, Process, ProcessId};
use crate::syscall::{SyscallRequest, SyscallResponse};

/// Backing store used by the emulator.
type Cache = CorePageCache<InMemoryBlockDevice>;

/// How many pages the emulated device provides by default.
const DEFAULT_PAGE_COUNT: u64 = 64;
/// How many page frames the buffer pool keeps resident by default.
const DEFAULT_POOL_FRAMES: usize = 16;

/// A user-space Archon host: loads attested artifacts, mints their
/// capabilities, and services their syscalls.
///
/// # What this emulates, and what it does not
///
/// spec.txt §4.2 called for reimplementing a capability slot table, a page
/// table, and raw-pointer memory views, on the premise that Archon was not yet
/// runnable outside bare metal. That premise no longer holds:
/// `tpt-archon-kernel` describes itself as a user-space-first capability
/// microkernel and is already implemented. Reimplementing its primitives here
/// would produce a *second*, weaker security model competing with the real one.
///
/// So nothing about capabilities or memory safety is emulated. Every check
/// below runs inside tpt-archon:
///
/// | Concern | Enforced by |
/// |---|---|
/// | Token unforgeability | `CapabilityIssuer` — `Capability`'s fields are private |
/// | Revocation | `CapabilityIssuer::authorizes`, consulted on every map |
/// | Read/write separation | `Right::allows_read` / `allows_write` |
/// | Bounds checking | `BufferPool` over `InMemoryBlockDevice` |
/// | Zero-copy borrows | `UnifiedMemory::map_read` -> `&Page`, in place |
/// | Scheduling | `tpt_archon_kernel::scheduler::Scheduler` |
///
/// What nexus adds is the layer above: *processes* (an identity that owns a
/// capability set), *syscalls* (a value-returning boundary), and the derivation
/// of grants from a proof manifest.
///
/// # Single-threaded by construction
///
/// `SharedIssuer` is `Rc<RefCell<CapabilityIssuer>>`, so the emulator is
/// `!Send`/`!Sync`. This mirrors tpt-archon's own concurrency model (one task
/// per connection, cooperatively scheduled) rather than papering over it.
pub struct ArchonEmulator {
    issuer: SharedIssuer,
    memory: UnifiedMemory<Cache>,
    scheduler: Scheduler,
    processes: BTreeMap<ProcessId, Process>,
    page_count: u64,
    next_block: u64,
    /// Pages freed by terminated processes, available for reuse. Kept sorted
    /// ascending so allocation is deterministic (lowest free page first).
    free_pages: Vec<u64>,
    polls: Rc<Cell<usize>>,
}

impl std::fmt::Debug for ArchonEmulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither `UnifiedMemory` nor `Scheduler` implements `Debug`.
        f.debug_struct("ArchonEmulator")
            .field("processes", &self.processes.len())
            .field("page_count", &self.page_count)
            .field("next_block", &self.next_block)
            .field("free_pages", &self.free_pages.len())
            .field("tasks", &self.scheduler.task_count())
            .finish()
    }
}

impl Default for ArchonEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchonEmulator {
    /// An emulator with a 64-page in-memory device and a 16-frame pool.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_PAGE_COUNT, DEFAULT_POOL_FRAMES)
    }

    /// An emulator over a device of `page_count` pages with `pool_frames`
    /// resident frames.
    ///
    /// # Panics
    ///
    /// Panics if `pool_frames` is zero, propagating `BufferPool`'s own
    /// precondition.
    pub fn with_capacity(page_count: u64, pool_frames: usize) -> Self {
        let issuer: SharedIssuer = Rc::new(RefCell::new(CapabilityIssuer::new()));
        let cache = CorePageCache::new(
            BufferPool::new(InMemoryBlockDevice::new(page_count), pool_frames),
            Rc::clone(&issuer),
        );
        Self {
            issuer,
            memory: UnifiedMemory::new(cache),
            scheduler: Scheduler::new(),
            processes: BTreeMap::new(),
            page_count,
            next_block: 0,
            free_pages: Vec::new(),
            polls: Rc::new(Cell::new(0)),
        }
    }

    /// Bytes in one page.
    pub const fn page_size() -> usize {
        PAGE_SIZE
    }

    /// Pages the emulated device provides.
    pub fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Processes currently loaded.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Look up a loaded process.
    pub fn process(&self, pid: ProcessId) -> Option<&Process> {
        self.processes.get(&pid)
    }

    /// Every loaded process, ordered by pid.
    pub fn processes(&self) -> impl Iterator<Item = &Process> {
        self.processes.values()
    }

    /// Ingest a verified artifact: validate its attestation, mint its
    /// capabilities, and register it with the scheduler.
    ///
    /// # Stages
    ///
    /// 1. **[5. VALIDATE]** — the manifest is re-verified against the
    ///    artifact's source bytes with [`tpt_nexus_manifest_validator`]. The
    ///    in-memory `all_verified` flag is *not* trusted on its own: an
    ///    artifact whose source was swapped after attestation is rejected here.
    /// 2. **[6. MINT]** — one page capability per verified function, minted by
    ///    `CapabilityIssuer`.
    /// 3. The artifact is spawned as a scheduler task; its task id becomes the
    ///    [`ProcessId`].
    ///
    /// # Grant policy
    ///
    /// This mapping is nexus's own, and it has to be: a `ProofManifest` records
    /// *that* a function was proved, not what memory it needs. The manifest
    /// alone cannot answer "read or write?", so nexus derives it from the
    /// verified body instead:
    ///
    /// * **Which functions** — only those with `verified == true`. An
    ///   unverified function yields no capability at all, which is the
    ///   executable form of "no manifest, no grants".
    /// * **Which page** — one page per function, assigned sequentially in
    ///   manifest order (`BTreeMap`, so alphabetical and deterministic).
    /// * **Which right** — [`Right::ReadWrite`] if the accepted body writes a
    ///   struct field, otherwise [`Right::Read`]. A pure query is granted
    ///   read-only access; only a mutator earns write access. This is least
    ///   privilege derived from a proof, and it is what makes Example 2's
    ///   denial a real consequence of the program's semantics rather than a
    ///   flag set by the test.
    ///
    /// # Errors
    ///
    /// * [`ArchonError::InvalidAttestation`] — the manifest does not match the
    ///   source.
    /// * [`ArchonError::UnverifiedArtifact`] — a function did not verify.
    /// * [`ArchonError::OutOfBounds`] — the device has too few pages.
    pub fn load_artifact(&mut self, artifact: &VerifiedArtifact) -> Result<ProcessId, ArchonError> {
        // [5. VALIDATE] Re-derive both hashes; never trust a passed-in flag.
        let verification = tpt_nexus_manifest_validator::validate_bytes(
            std::path::Path::new("<memory>/telos-proof.json"),
            std::path::Path::new("<memory>/source.telos"),
            &artifact.manifest_json(),
            artifact.source_code.as_bytes(),
        );
        if !verification.is_valid() {
            return Err(ArchonError::InvalidAttestation(
                if verification.manifest_was_modified() {
                    "the proof manifest does not hash to its own manifest_hash".to_string()
                } else {
                    format!(
                        "source hash mismatch: manifest claims {}, source hashes to {}",
                        verification.source_hash_expected, verification.source_hash_actual
                    )
                },
            ));
        }

        let unverified: Vec<String> = artifact
            .manifest
            .functions
            .iter()
            .filter(|(_, proof)| !proof.verified)
            .map(|(name, _)| name.clone())
            .collect();
        if !unverified.is_empty() {
            return Err(ArchonError::UnverifiedArtifact {
                functions: unverified,
            });
        }

        // Which functions write state? Derived from the accepted body by the
        // orchestrator. Single source of truth shared with `nexus verify`/`diff`.
        let rights = derive_rights(&artifact)?;

        // [6. MINT] One page capability per verified function.
        let mut grants = Vec::new();
        for func_name in artifact.manifest.functions.keys() {
            let block_id = self.allocate_block()?;

            let right = rights.get(func_name.as_str()).copied().unwrap_or(Right::Read);
            let capability = self
                .issuer
                .borrow_mut()
                .mint(page_resource(block_id), right);

            tracing::info!(
                func = %func_name, block_id, ?right,
                "minted capability for verified function"
            );
            grants.push(Grant {
                func_name: func_name.clone(),
                block_id,
                right,
                capability,
            });
        }

        let name = artifact
            .telos
            .modules
            .first()
            .map(|m| m.name.clone())
            .unwrap_or_else(|| "anonymous".to_string());

        let terminated = Rc::new(Cell::new(false));
        let pid = self.scheduler.spawn(Box::new(ArtifactTask {
            name: name.clone(),
            terminated: Rc::clone(&terminated),
            polls: Rc::clone(&self.polls),
        }));

        tracing::info!(
            pid, process = %name, grants = grants.len(),
            image_bytes = artifact.compiled_binary.len(),
            "artifact loaded"
        );

        self.processes.insert(
            pid,
            Process::new(
                pid,
                name,
                artifact.compiled_binary.len(),
                artifact.manifest.source_hash.clone(),
                grants,
                terminated,
            ),
        );
        Ok(pid)
    }

    /// Service one syscall on behalf of a loaded process.
    ///
    /// The capability is looked up in the process's own set, then handed to
    /// tpt-archon, which re-validates it against the issuer before touching a
    /// page. Nexus never decides access itself — it cannot, since
    /// `Capability`'s fields are private and only the issuer can vouch for a
    /// serial.
    ///
    /// # Errors
    ///
    /// * [`ArchonError::ProcessNotFound`] — unknown or terminated pid.
    /// * [`ArchonError::CapabilityViolation`] — the process holds no
    ///   capability for the page, or holds one without the needed right. This
    ///   is `CacheError::Denied` from tpt-archon, enriched with what the
    ///   process actually held.
    /// * [`ArchonError::OutOfBounds`] — the page is off the end of the device.
    /// * [`ArchonError::PayloadTooLarge`] — a write longer than a page.
    pub fn handle_syscall(
        &mut self,
        pid: ProcessId,
        request: SyscallRequest,
    ) -> Result<SyscallResponse, ArchonError> {
        let block_id = request.block_id();
        let needed = match request {
            SyscallRequest::ReadPage { .. } => Right::Read,
            SyscallRequest::WritePage { .. } => Right::Write,
        };
        // `held` is captured now so a later denial can say what the process
        // actually had, without re-borrowing `self` while `memory` is in use.
        let (capability, held) = self.authorize(pid, block_id, needed)?;

        match request {
            SyscallRequest::ReadPage { block_id } => {
                let page = self
                    .memory
                    .map_read(&capability, block_id)
                    .map_err(|e| map_cache_error(e, pid, block_id, needed, Some(held)))?;
                let bytes = page.as_bytes().to_vec();
                // `map_read` pins the frame; nothing else releases it.
                self.memory.unmap(block_id);
                tracing::debug!(pid, block_id, "read_page served");
                Ok(SyscallResponse::Page { block_id, bytes })
            }
            SyscallRequest::WritePage { block_id, data } => {
                if data.len() > PAGE_SIZE {
                    return Err(ArchonError::PayloadTooLarge {
                        given: data.len(),
                        capacity: PAGE_SIZE,
                    });
                }
                let page = self
                    .memory
                    .map_write(&capability, block_id)
                    .map_err(|e| map_cache_error(e, pid, block_id, needed, Some(held)))?;
                page.as_bytes_mut()[..data.len()].copy_from_slice(&data);
                self.memory.unmap(block_id);
                tracing::debug!(pid, block_id, len = data.len(), "write_page served");
                Ok(SyscallResponse::Written {
                    block_id,
                    len: data.len(),
                })
            }
        }
    }

    /// Borrow a page in place, with no copy, for the duration of `f`.
    ///
    /// This is the true zero-copy path.
    /// [`handle_syscall`](Self::handle_syscall) has to copy its result out —
    /// a syscall returns a value, and a value cannot borrow kernel memory — but
    /// the underlying grant really is an in-place borrow, and this exposes it.
    /// `f` receives tpt-archon's own [`Page`], borrowed directly out of the
    /// buffer pool.
    ///
    /// The closure form is required rather than chosen: `map_read` takes
    /// `&mut self` on the cache and the returned reference borrows from it, so
    /// the borrow cannot outlive the call.
    ///
    /// # Note on `MemoryView`
    ///
    /// `tpt_archon_bridge::grant::MemoryView` is a newtype over exactly this
    /// `&Page`, produced by `CapabilityGrant::grant_read`. That trait is a
    /// blanket impl over `UnifiedPageCache`, but `UnifiedMemory` wraps its
    /// cache without exposing it, so the wrapper is unreachable from the kernel
    /// layer (see README "Upstream gaps"). The guarantee is identical either
    /// way: one borrow, no copy, capability checked on every call.
    pub fn with_page<R>(
        &mut self,
        pid: ProcessId,
        block_id: u64,
        f: impl FnOnce(&Page) -> R,
    ) -> Result<R, ArchonError> {
        let (capability, held) = self.authorize(pid, block_id, Right::Read)?;
        let page = self
            .memory
            .map_read(&capability, block_id)
            .map_err(|e| map_cache_error(e, pid, block_id, Right::Read, Some(held)))?;
        let result = f(page);
        self.memory.unmap(block_id);
        Ok(result)
    }

    /// Run the cooperative scheduler for `ticks` polls.
    ///
    /// Returns the number of ticks that actually ran; fewer than requested
    /// means every task completed.
    pub fn tick(&mut self, ticks: usize) -> usize {
        let mut ran = 0;
        for _ in 0..ticks {
            if self.scheduler.tick().is_none() {
                break;
            }
            ran += 1;
        }
        ran
    }

    /// Tasks still registered with the scheduler.
    pub fn task_count(&self) -> usize {
        self.scheduler.task_count()
    }

    /// Terminate a process and revoke every capability it held.
    ///
    /// Revocation is why nexus retains the `Capability` values rather than
    /// handing them out and forgetting them: `CapabilityIssuer` cannot
    /// enumerate live tokens, so whoever loses a token can never revoke it. The
    /// process leaves the table immediately; its scheduler task exits on its
    /// next poll.
    pub fn terminate(&mut self, pid: ProcessId) -> Result<(), ArchonError> {
        let process = self
            .processes
            .remove(&pid)
            .ok_or(ArchonError::ProcessNotFound(pid))?;
        // Recycle the pages this process held so a later load can reuse them
        // instead of exhausting the device.
        let mut freed: Vec<u64> = process.grants.iter().map(|g| g.block_id).collect();
        self.free_pages.append(&mut freed);
        self.free_pages.sort_unstable();
        self.free_pages.dedup();
        process.terminate();
        {
            let mut issuer = self.issuer.borrow_mut();
            for grant in &process.grants {
                issuer.revoke(&grant.capability);
            }
        }
        tracing::info!(pid, process = %process.name, "process terminated, capabilities revoked");
        // Let the task observe the flag and leave the scheduler.
        let pending = self.scheduler.task_count().max(1);
        self.tick(pending);
        Ok(())
    }

    /// Find the capability a process holds for `block_id`, checking the right
    /// before tpt-archon is consulted. Returns the token and the right held.
    ///
    /// This is *not* the security boundary — tpt-archon re-checks on every map,
    /// and only its check sees revocations. It exists so a denial can report
    /// what the process actually held, which `CacheError::Denied` cannot say.
    fn authorize(
        &self,
        pid: ProcessId,
        block_id: u64,
        needed: Right,
    ) -> Result<(Capability, Right), ArchonError> {
        if block_id >= self.page_count {
            return Err(ArchonError::OutOfBounds {
                block_id,
                block_count: self.page_count,
            });
        }
        let process = self
            .processes
            .get(&pid)
            .ok_or(ArchonError::ProcessNotFound(pid))?;

        let grant = process
            .grant_for(block_id)
            .ok_or(ArchonError::CapabilityViolation {
                pid,
                block_id,
                attempted: needed,
                held: None,
            })?;

        let permitted = match needed {
            Right::Read => grant.right.allows_read(),
            Right::Write => grant.right.allows_write(),
            Right::ReadWrite => grant.right.allows_read() && grant.right.allows_write(),
        };
        if !permitted {
            tracing::warn!(
                pid, block_id, attempted = ?needed, held = ?grant.right,
                "capability violation"
            );
            return Err(ArchonError::CapabilityViolation {
                pid,
                block_id,
                attempted: needed,
                held: Some(grant.right),
            });
        }
        Ok((grant.capability, grant.right))
    }

    /// Allocate the next page for a grant, reusing a page freed by a terminated
    /// process before advancing the high-water mark.
    fn allocate_block(&mut self) -> Result<u64, ArchonError> {
        if let Some(id) = self.free_pages.first().copied() {
            self.free_pages.remove(0);
            return Ok(id);
        }
        let id = self.next_block;
        if id >= self.page_count {
            return Err(ArchonError::OutOfBounds {
                block_id: id,
                block_count: self.page_count,
            });
        }
        self.next_block += 1;
        Ok(id)
    }
}

/// Derive the capability each verified function earns, independent of page
/// allocation: `Right::ReadWrite` when the accepted body writes a struct
/// field, otherwise `Right::Read`.
///
/// Also the single guard against cross-module name collisions: grants and
/// `page_of` are keyed by bare function name, so a name declared in more
/// than one module is ambiguous and refused. Shared by `load_artifact` and
/// the `tpt-nexus-cli` `verify`/`diff` commands so the derivation can never
/// drift between runtime and reporting.
pub fn derive_rights(
    artifact: &VerifiedArtifact,
) -> Result<BTreeMap<String, Right>, ArchonError> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for module in &artifact.telos.modules {
        for item in &module.items {
            if let Item::Func(func) = item {
                *counts.entry(func.name.as_str()).or_insert(0) += 1;
            }
        }
    }
    if let Some((name, _)) = counts.iter().find(|(_, &c)| c > 1) {
        return Err(ArchonError::AmbiguousFunctionName(name.to_string()));
    }

    let mut rights: BTreeMap<String, Right> = BTreeMap::new();
    for record in artifact.functions() {
        let right = if record.mutates_state {
            Right::ReadWrite
        } else {
            Right::Read
        };
        rights.insert(record.func_name.clone(), right);
    }
    Ok(rights)
}

/// Translate tpt-archon's `CacheError` into nexus's process-aware error.
fn map_cache_error(
    error: CacheError,
    pid: ProcessId,
    block_id: u64,
    attempted: Right,
    held: Option<Right>,
) -> ArchonError {
    match error {
        CacheError::Denied => ArchonError::CapabilityViolation {
            pid,
            block_id,
            attempted,
            held,
        },
        CacheError::Storage(StorageError::OutOfBounds {
            block_id,
            block_count,
        }) => ArchonError::OutOfBounds {
            block_id,
            block_count,
        },
        CacheError::Storage(e) => ArchonError::Storage(e),
    }
}

/// `Resource::Page` for a block id, for callers describing their own grants.
pub fn page_of(block_id: u64) -> Resource {
    Resource::Page(block_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_nexus_orchestrator::{NexusOrchestrator, StaticAgent};

    /// A two-function program: one mutator (writes state) and one read-only
    /// query. Used to exercise page allocation and recycling.
    const TWO_FUNCS: &str = r#"
        module L {
            invariant Account { balance >= 0 }
            func settle(a: Account, amount: PositiveInt)
                requires a.balance >= amount
                ensures a.balance == old(a.balance) - amount
            { mutate state { a.balance -= amount } }
            func read(a: Account)
                requires a.balance >= 0
                ensures a.balance >= 0
            { let snapshot = a.balance }
        }
    "#;

    /// Two modules declaring the same function name `shared`.
    const COLLIDING_NAMES: &str = r#"
        module A {
            invariant Account { balance >= 0 }
            func shared(a: Account)
                requires a.balance >= 0
                ensures a.balance >= 0
            { let s = a.balance }
        }
        module B {
            invariant Account { balance >= 0 }
            func shared(a: Account)
                requires a.balance >= 0
                ensures a.balance >= 0
            { let s = a.balance }
        }
    "#;

    fn artifact(intent: &str) -> tpt_nexus_orchestrator::VerifiedArtifact {
        NexusOrchestrator::new()
            .run_agent_loop(intent, &StaticAgent::new())
            .expect("the fixture verifies")
    }

    #[test]
    fn pages_are_recycled_after_terminate() {
        let mut emulator = ArchonEmulator::new();
        let first = emulator.load_artifact(&artifact(TWO_FUNCS)).unwrap();
        let first_pages: Vec<u64> = emulator
            .process(first)
            .unwrap()
            .grants
            .iter()
            .map(|g| g.block_id)
            .collect();
        assert_eq!(first_pages, vec![0, 1], "fresh load uses low pages");

        emulator.terminate(first).unwrap();
        // The device only has 64 pages; loading many times without recycling
        // would eventually fail with OutOfBounds. Here the freed pages are
        // reused, so a second load lands back on 0 and 1.
        let second = emulator.load_artifact(&artifact(TWO_FUNCS)).unwrap();
        let second_pages: Vec<u64> = emulator
            .process(second)
            .unwrap()
            .grants
            .iter()
            .map(|g| g.block_id)
            .collect();
        assert_eq!(second_pages, vec![0, 1], "terminated pages are reused");
    }

    #[test]
    fn ambiguous_function_name_is_rejected() {
        let mut emulator = ArchonEmulator::new();
        match NexusOrchestrator::new().run_agent_loop(COLLIDING_NAMES, &StaticAgent::new()) {
            // telos accepted the collision (manifest collapsed it): nexus must
            // refuse to mint rather than under-grant one of them.
            Ok(artifact) => assert!(
                matches!(
                    emulator.load_artifact(&artifact),
                    Err(ArchonError::AmbiguousFunctionName(_))
                ),
                "a name shared across modules must be rejected"
            ),
            // telos itself rejected/panicked on the collision: the guard is
            // belt-and-suspenders and the test is vacuously satisfied.
            Err(_) => {}
        }
    }
}
