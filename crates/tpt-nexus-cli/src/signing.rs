//! Signed attestations: make an attestation *tamper-evident*, not just
//! checkable.
//!
//! A `ProofManifest` already proves that the manifest matches the source (the
//! validator re-derives both hashes). But anyone can re-run the verifier and
//! re-issue a manifest for edited code — the hash only proves *internal*
//! consistency, not *authorship*. An ed25519 signature over the manifest
//! document, made with a project's signing key, closes that gap: a manifest is
//! trustworthy only if it carries a signature from a key the project trusts.
//!
//! Signing is optional and opt-in: `nexus sign` produces a `.sig` file; `nexus
//! verify` (or any reviewer) checks it against the project's published public
//! key. No signing key is ever written into the manifest.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;

/// An ed25519 keypair for signing attestations.
#[derive(Debug, Clone)]
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a fresh signing keypair from OS randomness.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Keypair {
            signing: SigningKey::from_bytes(&secret),
        }
    }

    /// Reconstruct a keypair from a 32-byte hex-encoded secret key.
    pub fn from_secret_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex_decode(hex).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("secret key must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Keypair {
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// The public key as a hex string, for publishing / verification.
    pub fn public_hex(&self) -> String {
        hex_encode(&self.signing.verifying_key().to_bytes())
    }

    /// Sign a message, returning the 64-byte raw signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }
}

/// Hex-encode bytes (used for the on-disk signature file).
pub fn to_hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

/// Hex-decode a string (used to read a written signature back).
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex_decode(s)
}

/// Verify a signature (raw 64 bytes) against a hex public key and a message.
///
/// Returns `false` on any malformed input — a bad key, a wrong-length
/// signature, or a genuine mismatch — so callers can treat `false` uniformly as
/// "do not trust this manifest".
pub fn verify(public_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    let key_bytes = match hex_decode(public_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig).is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has an odd length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(format!("invalid hex digit: {}", other as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_round_trips() {
        let key = Keypair::generate();
        let msg = b"telos-proof.json contents";
        let sig = key.sign(msg);
        assert!(verify(&key.public_hex(), msg, &sig));
        assert!(!verify(&key.public_hex(), b"tampered", &sig));
    }

    #[test]
    fn wrong_key_rejects() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let msg = b"hello";
        let sig = a.sign(msg);
        assert!(!verify(&b.public_hex(), msg, &sig));
    }

    #[test]
    fn malformed_inputs_reject_cleanly() {
        let key = Keypair::generate();
        let sig = key.sign(b"x");
        assert!(!verify("not-hex", b"x", &sig));
        assert!(!verify(&key.public_hex(), b"x", b"short"));
        assert!(Keypair::from_secret_hex("zz").is_err());
    }
}
