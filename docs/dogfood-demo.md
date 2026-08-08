# Dogfooding the nexus capability gate

This repo ships a capability-regression gate (`nexus verify` via the
`nexus-verify` composite action) and runs it on every PR through
`.github/workflows/nexus-verify-pr.yml`. This document is a reproducible recipe
for producing the "sticky-comment + failed check" screenshot on demand, without
leaving a permanently broken example in `examples/`.

## What it proves

The gate catches a silent escalation: a function that used to be a read-only
query becomes a state mutator (so its derived capability escalates
`Read -> ReadWrite`). The PR comment shows the before/after table and the step
fails when `fail-on-strengthening` is true.

## Recipe

1. Start from `main` on a scratch branch:

   ```text
   git switch -c dogfood/strengthening-demo
   ```

2. Take a pure-query function and turn it into a mutator. The example below
   edits `examples/diff_demo_before.telos` (a read-only lookup) into a body
   that writes state:

   ```diff
    func balance_of(a: Account)
        requires a.balance >= 0
        ensures a.balance >= 0
    - { let b = a.balance }
    + {
    +     mutate state {
    +         a.balance += 1
    +     }
    + }
   ```

   (Equivalently, copy `examples/diff_demo_before.telos` to a new path and edit
   that, to avoid touching the committed example.)

3. Commit and open a PR:

   ```text
   git add -A
   git commit -m "demo: silently escalate a read-only query"
   git push -u origin dogfood/strengthening-demo
   # open the PR in the GitHub UI
   ```

4. Watch the `nexus verify (PR)` check:

   - The check **fails** (exit 1 from the `diff` step) because `balance_of`
     escalated from `Read` to `ReadWrite`.
   - A sticky comment titled `nexus-capabilities` is posted showing the
     per-file capability table and the `Read -> ReadWrite` change.

5. To confirm the *clean* path, push the original read-only body back and the
   check turns green and the comment updates.

## Notes

- The gate diffs the candidate against `origin/<base_ref>` (the PR base), so the
  escalation is only visible as a regression when the base branch still has the
  read-only version.
- `fail-on-strengthening` is on by default. Set it to `"false"` in the workflow
  (or call the composite action with `fail-on-strengthening: "false"`) if you
  want the comment without failing the PR.

The same escalation, framed as a supply-chain "refactor", is also exercised
non-interactively by `.github/workflows/nexus-security-scan.yml` via
`examples/supply_chain_before.telos` -> `examples/supply_chain_after.telos`.
