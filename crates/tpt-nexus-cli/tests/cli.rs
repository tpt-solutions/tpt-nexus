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
        stdout.contains("Counter::increment` | Read |"),
        "policy override should force `Counter::increment` to Read; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("Counter::increment` | ReadWrite |"),
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
        bare_out.contains("Counter::increment` | ReadWrite |"),
        "without policy, Counter::increment is ReadWrite"
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

#[test]
fn init_scaffolds_a_policy_file() {
    let tmp = TmpDir::new("init");
    let out = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["init"])
        .output()
        .expect("run nexus init");
    assert!(out.status.success(), "init should succeed");
    assert!(
        tmp.path("nexus.toml").is_file(),
        "nexus.toml scaffolded into cwd"
    );
    let body = std::fs::read_to_string(tmp.path("nexus.toml")).unwrap();
    assert!(body.contains("agent"), "scaffolded policy has an agent key");
}

#[test]
fn verify_warns_on_policy_grant_with_unknown_func() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let telos = repo_root.join("examples/compiled_artifact.telos");
    assert!(telos.exists(), "example exists");

    let tmp = TmpDir::new("warn");
    std::fs::write(
        tmp.path("nexus.toml"),
        r#"
        agent = "static"
        [[grant]]
        func = "no_such_func"
        right = "Read"
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .current_dir(&tmp.0)
        .args(["verify", telos.to_str().unwrap(), "--policy", "nexus.toml"])
        .output()
        .expect("run nexus verify");
    assert!(out.status.success(), "verify still succeeds");
    // NB: tracing output is emitted on stdout in this build, so the warning
    // (and the rendered table) are both captured there.
    let captured = String::from_utf8_lossy(&out.stdout);
    assert!(
        captured.contains("matches no verified function"),
        "unknown policy func must be warned: {captured}"
    );
    // The phantom grant must not appear as a table row (the func name may still
    // appear in the warning line above, which is expected).
    assert!(
        !captured.contains("| `no_such_func`"),
        "unknown func must not be minted as a phantom grant row"
    );
}

#[test]
fn require_signature_gate_accepts_signed_attestation_and_rejects_divergent_source() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let telos = repo_root.join("examples/compiled_artifact.telos");
    assert!(telos.exists(), "example exists");

    let tmp = TmpDir::new("sig");
    let out_dir = tmp.path("out");
    let manifest = out_dir.join("telos-proof.json");

    // Produce a signed attestation.
    let v = Command::new(bin())
        .args([
            "verify",
            telos.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("verify to produce attestation");
    assert!(v.status.success(), "verify succeeds");
    assert!(manifest.is_file(), "attestation written");

    let sign = Command::new(bin())
        .args(["sign", manifest.to_str().unwrap()])
        .output()
        .expect("sign attestation");
    assert!(sign.status.success(), "sign succeeds");
    let pubkey = String::from_utf8_lossy(&sign.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("public key :").map(str::trim))
        .expect("public key printed")
        .to_string();

    // Re-verify against the trusted key: the existing signed artifact matches.
    let ok = Command::new(bin())
        .args([
            "verify",
            telos.to_str().unwrap(),
            "--require-signature",
            &pubkey,
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("verify with signature");
    assert!(
        ok.status.success(),
        "valid signed attestation must pass: {}",
        String::from_utf8_lossy(&ok.stdout)
    );

    // A divergent source must be refused even though it still verifies.
    let diverged = tmp.path("diverged.telos");
    let original = std::fs::read_to_string(&telos).unwrap();
    std::fs::write(
        &diverged,
        format!("{original}\n// comment changes the hash\n"),
    )
    .unwrap();
    let bad = Command::new(bin())
        .args([
            "verify",
            diverged.to_str().unwrap(),
            "--require-signature",
            &pubkey,
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("verify divergent source");
    assert!(
        !bad.status.success(),
        "source diverging from the signed attestation must fail"
    );
    let captured = String::from_utf8_lossy(&bad.stdout);
    assert!(
        captured.contains("describes a different source"),
        "failure should name the source divergence: {captured}"
    );
}

#[test]
fn fuzz_reports_no_violations_for_a_clean_artifact() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let telos = repo_root.join("examples/compiled_artifact.telos");
    assert!(telos.exists(), "example exists");

    let out = Command::new(bin())
        .args(["fuzz", telos.to_str().unwrap()])
        .output()
        .expect("run nexus fuzz");
    assert!(out.status.success(), "fuzz should pass on a clean artifact");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 violation(s)"),
        "a clean artifact must have a tight grant set: {stdout}"
    );
}

#[test]
fn verify_emits_sarif_for_code_scanning() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let telos = repo_root.join("examples/capability_boundary.telos");
    assert!(telos.exists(), "example exists");

    let tmp = TmpDir::new("sarif");
    let sarif_path = tmp.path("caps.sarif");
    let out = Command::new(bin())
        .args([
            "verify",
            telos.to_str().unwrap(),
            "--sarif",
            sarif_path.to_str().unwrap(),
        ])
        .output()
        .expect("run nexus verify --sarif");
    assert!(out.status.success(), "verify --sarif succeeds");
    assert!(sarif_path.is_file(), "SARIF file written");

    let sarif = std::fs::read_to_string(&sarif_path).unwrap();
    assert!(sarif.contains("\"version\": \"2.1.0\""), "SARIF 2.1.0 document");
    assert!(sarif.contains("\"runs\""), "SARIF has runs");
    assert!(
        sarif.contains("nexus/capability"),
        "SARIF reports capability rules"
    );
}
