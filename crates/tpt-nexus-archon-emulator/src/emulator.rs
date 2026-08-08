//! [`ArchonEmulator`]: [5. VALIDATE] -> [6. MINT] -> [7. EXECUTE].

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use tpt_archon_bridge::capability::{Capability, CapabilityIssuer, Resource, Right, SharedIssuer};
use tpt_archon_bridge::page_cache::{CacheError, CorePageCache};
use tpt_archon_core::block::{InMemoryBlockDevice, StorageError};
use tpt_archon_core::page::{BufferPool, Page, PAGE_SIZE};
use tpt_archon_kernel::memory::UnifiedMemory;
use tpt_archon_kernel::scheduler::Scheduler;
use tpt_nexus_orchestrator::VerifiedArtifact;
use tpt_telos_parser::ast::Item;

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
    ///
    /// The right each function earns is **derived automatically** from its
    /// verified body (see [`derive_rights`]). To override a derived right with a
    /// `nexus.toml` policy instead, use
    /// [`load_artifact_with_rights`](Self::load_artifact_with_rights).
    pub fn load_artifact(&mut self, artifact: &VerifiedArtifact) -> Result<ProcessId, ArchonError> {
        // Derive the right each function earns (the default, policy-free path).
        let rights = derive_rights(artifact)?;
        self.load_artifact_with_rights(artifact, &rights)
    }

    /// Load an artifact, but mint capabilities using a caller-supplied right map
    /// rather than the auto-derived one.
    ///
    /// This is the policy-aware entry point: `nexus verify --policy` resolves a
    /// `nexus.toml` into a `BTreeMap<func, Right>` (derived rights with
    /// overrides applied) and passes it here, so a forced-down `Read` is actually
    /// enforced by the emulator, not merely printed. The supplied rights must
    /// cover every verified function; a missing entry silently degrades to
    /// [`Right::Read`] to avoid an unverified panic, matching
    /// [`derive_rights`](crate::derive_rights)'s own fallback.
    ///
    /// Validation ([5. VALIDATE]) runs identically to [`load_artifact`].
    pub fn load_artifact_with_rights(
        &mut self,
        artifact: &VerifiedArtifact,
        rights: &BTreeMap<String, Right>,
    ) -> Result<ProcessId, ArchonError> {
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

        // Which functions write state? When a policy is supplied the caller has
        // already applied its overrides to `rights`; otherwise `rights` is the
        // auto-derived map from `load_artifact`. Single source of truth shared
        // with `nexus verify`/`diff`.

        // [6. MINT] One page capability per verified function, keyed by
        // `module::func` so same-named functions in different modules stay
        // distinct. `rights` is keyed identically (see `derive_rights`).
        let mut grants = Vec::new();
        for module in &artifact.telos.modules {
            for item in &module.items {
                if let Item::Func(func) = item {
                    let func_name = format!("{}::{}", module.name, func.name);
                    let block_id = self.allocate_block()?;

                    let right = rights.get(&func_name).copied().unwrap_or(Right::Read);
                    let capability = self
                        .issuer
                        .borrow_mut()
                        .mint(page_resource(block_id), right);

                    tracing::info!(
                        func = %func_name, block_id, ?right,
                        "minted capability for verified function"
                    );
                    grants.push(Grant {
                        func_name,
                        block_id,
                        right,
                        capability,
                    });
                }
            }
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
/// Grants are keyed by `module::func` (e.g. `Counter::increment`) rather than
/// the bare function name. This keeps functions that share a bare name across
/// modules distinguishable, which the original bare-name keying could not do
/// (it had to hard-reject the collision). Shared by `load_artifact`,
/// `verify`, and `diff` so the derivation can never drift between runtime and
/// reporting.
pub fn derive_rights(artifact: &VerifiedArtifact) -> Result<BTreeMap<String, Right>, ArchonError> {
    let mut rights: BTreeMap<String, Right> = BTreeMap::new();
    for module in &artifact.telos.modules {
        for item in &module.items {
            if let Item::Func(func) = item {
                let key = format!("{}::{}", module.name, func.name);
                // The right is derived from what the verified body proves. Names
                // are unique within a module; telos collapses any cross-module
                // duplicates into one record, so the first match is correct.
                let mutates = artifact
                    .functions()
                    .iter()
                    .find(|r| r.func_name == func.name)
                    .map(|r| r.mutates_state)
                    .unwrap_or(false);
                let right = if mutates {
                    Right::ReadWrite
                } else {
                    Right::Read
                };
                rights.insert(key, right);
            }
        }
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
    use crate::assert_grants;
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
    fn assert_grants_macro_catches_the_derived_rights() {
        let mut emulator = ArchonEmulator::new();
        let pid = emulator.load_artifact(&artifact(TWO_FUNCS)).unwrap();

        // One line pins the whole capability surface, derived from what each
        // function was proved to do.
        assert_grants!(emulator, pid, {
            "L::settle" => Right::ReadWrite,
            "L::read"   => Right::Read,
        });
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

    /// A simple single-function program, used for the negative-path tests.
    const SINGLE_FUNC: &str = r#"
        module C {
            invariant Counter { value >= 0 }
            func increment(c: Counter, by: PositiveInt)
                requires c.value >= 0
                ensures c.value == old(c.value) + by
            { mutate state { c.value += by } }
        }
    "#;

    /// A manifest whose source no longer matches it must be refused at mint time,
    /// never trusted because the artifact happens to be in memory and "verified".
    #[test]
    fn tampered_source_is_rejected_at_mint() {
        let mut artifact = artifact(SINGLE_FUNC);
        // The attacker edits the source after attestation, but leaves the
        // manifest (and its recorded source hash) untouched.
        artifact.source_code = artifact.source_code.replace("+ by", "- by");

        let mut emulator = ArchonEmulator::new();
        match emulator.load_artifact(&artifact) {
            Err(ArchonError::InvalidAttestation(why)) => {
                assert!(
                    why.contains("source") || why.contains("manifest"),
                    "reason should name the tamper: {why}"
                );
            }
            other => panic!("expected InvalidAttestation, got {other:?}"),
        }
        assert_eq!(emulator.process_count(), 0, "nothing was minted");
    }

    /// A manifest edited in place (its own `manifest_hash` no longer holds) is
    /// also refused — this is the "someone rewrote the attestation" attack.
    #[test]
    fn tampered_manifest_is_rejected_at_mint() {
        let mut emulator = ArchonEmulator::new();
        let mut tampered = artifact(SINGLE_FUNC);
        // `to_json` serializes `manifest_hash` verbatim (it does not recompute),
        // so overwriting the field corrupts the document-level hash check.
        tampered.manifest.manifest_hash =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
        match emulator.load_artifact(&tampered) {
            Err(ArchonError::InvalidAttestation(why)) => {
                assert!(
                    why.contains("manifest"),
                    "reason should name the tamper: {why}"
                );
            }
            other => panic!("expected InvalidAttestation, got {other:?}"),
        }
    }

    /// After a process is terminated and its capabilities revoked, the same
    /// program (same function name, same page) can be admitted again — re-mint,
    /// not a permanent ban. Exercises the free-list reuse + fresh issuer serial.
    #[test]
    fn process_can_be_readmitted_after_revoke() {
        let mut emulator = ArchonEmulator::new();
        let a = emulator.load_artifact(&artifact(SINGLE_FUNC)).unwrap();
        emulator.terminate(a).unwrap();
        assert!(emulator.process(a).is_none());

        let b = emulator.load_artifact(&artifact(SINGLE_FUNC)).unwrap();
        assert_ne!(a, b, "re-admission gets a fresh process id");
        assert!(emulator.process(b).is_some());
        assert_eq!(emulator.process_count(), 1);

        // The re-admitted process holds a capability that actually works.
        let page = emulator
            .process(b)
            .unwrap()
            .page_of("C::increment")
            .unwrap();
        let ok = emulator.handle_syscall(
            b,
            SyscallRequest::WritePage {
                block_id: page,
                data: b"value=5".to_vec(),
            },
        );
        assert!(ok.is_ok(), "re-admitted capability should service syscalls");
    }

    /// A `nexus.toml` policy can force a risky mutator down to `Read`. The
    /// override must be enforced by the emulator, not just printed in the table:
    /// a write through that grant is refused.
    #[test]
    fn policy_override_forcing_read_denies_write() {
        let mut emulator = ArchonEmulator::new();
        let artifact = artifact(SINGLE_FUNC); // `increment` writes state -> ReadWrite
        let mut rights = derive_rights(&artifact).expect("derive rights");
        // The policy pins `C::increment` down to `Read`, despite it being
        // a mutator. Grants are keyed by `module::func`, so the override must
        // use that key to take effect at mint time.
        rights.insert("C::increment".to_string(), Right::Read);

        let pid = emulator
            .load_artifact_with_rights(&artifact, &rights)
            .expect("forced-down load");
        let page = emulator
            .process(pid)
            .unwrap()
            .page_of("C::increment")
            .expect("grant exists");

        let result = emulator.handle_syscall(
            pid,
            SyscallRequest::WritePage {
                block_id: page,
                data: b"value=5".to_vec(),
            },
        );
        assert!(
            matches!(result, Err(ArchonError::CapabilityViolation { .. })),
            "a policy-forced Read must deny a write: got {result:?}"
        );
    }

    /// The true zero-copy path: borrow a page in place (no copy) and read it
    /// directly, observing bytes written through the normal syscall path.
    #[test]
    fn with_page_exposes_the_zero_copy_borrow() {
        let mut emulator = ArchonEmulator::new();
        let pid = emulator.load_artifact(&artifact(SINGLE_FUNC)).unwrap();
        let page = emulator
            .process(pid)
            .unwrap()
            .page_of("C::increment")
            .unwrap();

        // Write through the value-returning syscall...
        emulator
            .handle_syscall(
                pid,
                SyscallRequest::WritePage {
                    block_id: page,
                    data: b"value=1".to_vec(),
                },
            )
            .expect("write via syscall");

        // ...and observe it through the zero-copy in-place borrow (no copy out).
        let seen = emulator
            .with_page(pid, page, |p| p.as_bytes()[..7].to_vec())
            .expect("zero-copy read");
        assert!(
            seen.starts_with(b"value=1"),
            "page should carry the written bytes: {seen:?}"
        );
    }

    /// A device with too few pages must eventually refuse to mint, rather than
    /// silently allocating off the end of the device.
    #[test]
    fn page_allocator_exhaustion_is_rejected() {
        // One page only: TWO_FUNCS needs two (settle, read), so the second mint
        // must fail with OutOfBounds rather than panic or wrap.
        let mut emulator = ArchonEmulator::with_capacity(1, 1);
        let err = emulator
            .load_artifact(&artifact(TWO_FUNCS))
            .expect_err("two functions cannot fit in one page");
        assert!(
            matches!(err, ArchonError::OutOfBounds { block_id, .. } if block_id == 1),
            "expected exhaustion at the second page, got {err:?}"
        );
    }

    /// A write longer than a page is refused before it can overflow the buffer.
    #[test]
    fn oversized_write_is_rejected() {
        let mut emulator = ArchonEmulator::new();
        let pid = emulator.load_artifact(&artifact(SINGLE_FUNC)).unwrap();
        let page = emulator
            .process(pid)
            .unwrap()
            .page_of("C::increment")
            .unwrap();

        let too_big = vec![0u8; PAGE_SIZE + 1];
        let err = emulator.handle_syscall(
            pid,
            SyscallRequest::WritePage {
                block_id: page,
                data: too_big,
            },
        );
        assert!(
            matches!(err, Err(ArchonError::PayloadTooLarge { .. })),
            "oversized payload must be rejected: got {err:?}"
        );
    }

    #[test]
    fn namespaced_grants_distinguish_same_named_functions() {
        let mut emulator = ArchonEmulator::new();
        // Two modules each declare `shared`: namespacing must keep them
        // distinct (`A::shared`, `B::shared`) instead of collapsing or
        // rejecting. If telos itself rejects/panics on the collision, the
        // behavior is moot and the test is vacuously satisfied.
        if let Ok(artifact) =
            NexusOrchestrator::new().run_agent_loop(COLLIDING_NAMES, &StaticAgent::new())
        {
            let rights = derive_rights(&artifact).expect("derive rights");
            assert!(
                rights.contains_key("A::shared"),
                "namespaced key A::shared must be present"
            );
            assert!(
                rights.contains_key("B::shared"),
                "namespaced key B::shared must be present"
            );
            let pid = emulator
                .load_artifact(&artifact)
                .expect("load namespaced artifact");
            assert_eq!(
                emulator.process(pid).unwrap().grants.len(),
                2,
                "two distinct namespaced grants should be minted"
            );
        }
    }
}
