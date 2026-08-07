# tpt-nexus starter templates

Copy one of these with `nexus new <name> --template <template>`:

```text
nexus new my_service --template ledger
```

Each file is a minimal, already-verifiable `.telos` program plus a natural
demonstration of the capability-derivation rules (a mutator earns `ReadWrite`,
a pure query earns `Read`).

| Template | What it shows |
|----------|---------------|
| `counter` | A single mutator (`increment`) that writes `Counter.value`. |
| `kv_store` | A mutator (`put`) and a pure query (`get`) in one module — good for a first `nexus diff`. |
| `ledger` | A single debit (`settle`) that writes `Account.balance`. |
| `oracle` | A pure-read function (`latest`) that reads `Price.price` — derived as `Read`. |
| `rate_limiter` | A single mutator (`allow`) that increments `Bucket.count` under a capacity invariant. |

## Pinning the capability surface

Once you have a `.telos` program, add a `nexus.toml` next to it to pin the
security surface in version control:

```toml
# "static" (default) or "llm"
agent = "static"

[[grant]]
func  = "settle"
right = "ReadWrite"   # force a function's derived right
```

Run `nexus verify your_file.telos --policy nexus.toml` to apply it.
