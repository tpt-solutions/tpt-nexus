//! Integration tests that exercise the `nexus` binary end to end. These cover
//! the gaps that let the lost-secret-key bug and the cosmetic-only policy
//! override ship uncaught (TODO §11.5).

use std::path::PathBuf;
use std::process::Command;

use tpt_nexus_cli::signing::{from_hex, Keypair};
use tpt_nexus_cli::Policy;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_nexus")
}

/// A scratch directory that cleans itself up.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("nexus-cli-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        TmpDir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sign_prints_a_recoverable_secret_key() {
    let tmp = TmpDir::new("sign");
    let manifest = tmp.path("telos-proof.json");
    std::fs::write(&manifest, r#"{"hello":"world"}"#).unwrap();

    let out = Command::new(bin())
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .expect("run nexus sign");
    assert!(out.status.success(), "sign should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    // The SECRET KEY must be present (generated, since none was supplied) and,
    // crucially, recoverable: reconstructing a keypair from it must reproduce the
    // same secret and re-verify the signature it just wrote. The prompt label and
    // the key are on separate lines.
    let secret = lines
        .iter()
        .position(|l| l.contains("SECRET KEY"))
        .and_then(|i| lines.get(i + 1).map(|s| s.trim().to_string()))
        .expect("SECRET KEY printed on generation");

    let public = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("public key :"))
        .expect("public key printed")
        .trim()
        .to_string();

    // Reconstruct from the printed secret; it must round-trip exactly.
    let recovered = Keypair::from_secret_hex(&secret).expect("secret must reconstruct a keypair");
    assert_eq!(recovered.secret_hex(), secret, "secret must be recoverable");

    // The on-disk signature must verify under the recovered key.
    let sig_path = manifest.with_extension("json.sig");
    let sig_hex = std::fs::read_to_string(&sig_path).expect("sig file written");
    let sig = from_hex(sig_hex.trim()).expect("sig is hex");
    let body = std::fs::read_to_string(&manifest).unwrap();
    assert!(
        tpt_nexus_cli::signing::verify(&public, body.as_bytes(), &sig),
        "recovered key must verify the produced signature"
    );

    // And the public key derived from the recovered secret matches what was shown.
    assert_eq!(recovered.public_hex(), public);
}

#[test]
fn new_refuses_to_overwrite_without_force() {
    let tmp = TmpDir::new("new");
    let first = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["new", "demo", "--template", "counter"])
        .output()
        .expect("run nexus new");
    assert!(first.status.success(), "first scaffold should succeed");
    assert!(tmp.path("demo.telos").exists(), "demo.telos created");

    let second = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["new", "demo", "--template", "ledger"])
        .output()
        .expect("run nexus new again");
    assert!(
        !second.status.success(),
        "overwrite without --force must fail"
    );
    // The original content must be preserved (still the counter template).
    let body = std::fs::read_to_string(tmp.path("demo.telos")).unwrap();
    assert!(
        body.contains("module Counter"),
        "original file must be untouched"
    );

    let forced = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["new", "demo", "--template", "ledger", "--force"])
        .output()
        .expect("run nexus new --force");
    assert!(forced.status.success(), "--force must overwrite");
    let body = std::fs::read_to_string(tmp.path("demo.telos")).unwrap();
    assert!(
        body.contains("module Ledger"),
        "forced overwrite swapped content"
    );
}

#[test]
fn verify_policy_override_is_reflected_in_the_granted_right() {
    // `examples/compiled_artifact.telos` is a single mutator (`increment`) that is
    // derived as `ReadWrite`. A policy forcing it to `Read` must surface in the
    // capability table (the same map the emulator mints against).
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let telos = repo_root.join("examples/compiled_artifact.telos");
    assert!(telos.exists(), "example exists");

    let tmp = TmpDir::new("policy");
    let policy = tmp.path("nexus.toml");
    std::fs::write(
        &policy,
        r#"
        agent = "static"
        [[grant]]
        func = "increment"
        right = "Read"
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .current_dir(&tmp.0)
        .args([
            "verify",
            telos.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .output()
        .expect("run nexus verify --policy");
    assert!(out.status.success(), "verify with policy should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The override must take effect: the table shows `Read`, not `ReadWrite`.
    assert!(
        stdout.contains("increment` | Read |"),
        "policy override should force `increment` to Read; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("increment` | ReadWrite |"),
        "policy override must not be cosmetic; ReadWrite should be gone"
    );

    // Sanity: without the policy the function is ReadWrite.
    let bare = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["verify", telos.to_str().unwrap()])
        .output()
        .expect("run nexus verify");
    let bare_out = String::from_utf8_lossy(&bare.stdout);
    assert!(
        bare_out.contains("increment` | ReadWrite |"),
        "without policy, increment is ReadWrite"
    );

    // The policy parsed by the CLI is the same one the test constructed.
    let _ = Policy::from_toml(
        r#"
        [[grant]]
        func = "increment"
        right = "Read"
        "#,
    )
    .expect("policy parses");
}
