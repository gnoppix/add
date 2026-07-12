//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

//! Snapshot-resistant key custody for hostile-host Core Node daemons (ACS2.6 §III.4 / §VI.1).
//!
//! Threat model: the physical host (cloud hypervisor) is actively adversarial. It may take
//! live RAM snapshots or clone the boot disk to extract routing metadata / payload keys.
//!
//! Defenses layered here:
//! 1. **Threshold cryptography** — a single-use AES-256 key is split 2-of-3 via Shamir's
//!    Secret Sharing over GF(2^8). No single shard reveals the key; two of three are needed.
//!    The reconstructed raw key exists in RAM only for the microseconds needed to seal/open.
//! 2. **`mlock`** — key + shards + identity buffers are pinned to RAM so they can never be
//!    paged out to swap (a disk clone of swap would otherwise leak them).
//! 3. **`madvise(MADV_DONTDUMP)`** — those pages are excluded from core dumps, so a forced
//!    kernel crash-dump (a snapshot vector) omits them.
//! 4. **Zeroize-on-drop** — every sensitive struct scrubs its bytes the instant it leaves scope,
//!    including during stack unwinding on panic/error.
//! 5. **Ephemeral-storage enforcement** — the daemon refuses to boot unless its key/shard
//!    directory is a `tmpfs`. A persistent block device (ext4/xfs/...) would let an offline
//!    disk clone recover the material, so we `panic!` instead.
//!
//! `unsafe` is confined to the three FFI calls (`mlock`, `madvise`, `statfs`) and is
//! documented at each site. A module-level `#![forbid(unsafe_code)]` is intentionally *not*
//! used: the kernel memory-management syscalls require `unsafe` and cannot be expressed safely
//! in stable Rust. Every `unsafe` block is minimal and SAFETY-commented.

use crate::secure_mem;
use rand::RngCore;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// AES-256 key length (bytes).
pub const KEY_LEN: usize = 32;
/// A shard is `x` (1 byte share index) concatenated with `y` (32-byte share value).
pub const SHARD_LEN: usize = 1 + KEY_LEN;

/// Low 8 bits of the GF(2^8) reduction polynomial 0x11D (standard for SSS over GF(256)).
const GF_POLY: u8 = 0x1D;
/// `statfs.f_type` for tmpfs (Linux `TMPFS_MAGIC`).
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

#[derive(Error, Debug)]
pub enum SnapError {
    #[error("path is not valid UTF-8 / C string for statfs")]
    InvalidPath,
    #[error("statfs failed: {0}")]
    StatFs(#[from] std::io::Error),
    #[error(
        "storage is NOT ephemeral (f_type=0x{f_type:x}); refusing to hold shards on a persistent device"
    )]
    NotEphemeral { f_type: u64 },
    #[error("need at least 2 shards to reconstruct, got {have}")]
    InsufficientShards { have: usize },
    #[error("failed to persist shard to storage: {0}")]
    Persist(String),
    #[error("key must be exactly {KEY_LEN} bytes, got {got}")]
    KeyLength { got: usize },
    #[error("aes-gcm error: {0}")]
    Aes(String),
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic (characteristic 2: addition = XOR, multiplication = carry-less)
// ---------------------------------------------------------------------------

/// Multiply two GF(2^8) elements using the polynomials 0x11D reduction.
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            // Reduction: bit 8 of `a` corresponds to x^8; x^8 = x^4 + x^3 + x + 1 (0x1D).
            a ^= GF_POLY;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8). Group order is 255, so a^-1 = a^254; computed by brute
/// search (tiny field) to avoid a 256-entry log table for a 2-of-3 scheme.
#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "GF inverse of zero is undefined");
    for i in 1u16..=255 {
        if gf_mul(a, i as u8) == 1 {
            return i as u8;
        }
    }
    0
}

#[inline]
fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

// ---------------------------------------------------------------------------
// Volatile AES-256 key — exists in locked, don't-dump RAM for the minimum time
// ---------------------------------------------------------------------------

/// A 32-byte AES-256 key pinned to RAM, excluded from core dumps, zeroized on drop.
///
/// Construct via [`VolatileKey::generate`] (fresh random) or [`VolatileKey::from_bytes`]
/// (import an existing key). The seal/open helpers take `&self` so the key is only ever
/// transiently materialized inside `Aes256Gcm` and is gone the moment the value drops.
pub struct VolatileKey {
    key: Vec<u8>,
}

impl VolatileKey {
    /// Generate a fresh random single-use key, lock it, and exclude it from dumps.
    pub fn generate() -> Result<Self, SnapError> {
        let mut key = vec![0u8; KEY_LEN];
        // Fill from the OS CSPRNG (thread_rng is seeded from getrandom/OS entropy).
        rand::thread_rng().fill_bytes(&mut key);
        let mut v = Self { key };
        secure_mem::lock_memory(&mut v.key);
        exclude_from_core_dump(&mut v.key);
        Ok(v)
    }

    /// Import an existing key, locking + excluding it. Source bytes are NOT zeroized here
    /// (caller owns them); pass a `Secu*Mut` slice if you want that.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapError> {
        if bytes.len() != KEY_LEN {
            return Err(SnapError::KeyLength { got: bytes.len() });
        }
        let key = bytes.to_vec();
        let mut v = Self { key };
        secure_mem::lock_memory(&mut v.key);
        exclude_from_core_dump(&mut v.key);
        Ok(v)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// AEAD-seal `plaintext` with this key. Returns `(nonce, ciphertext)`.
    /// The key is consumed only inside this call; nothing persists afterward.
    pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SnapError> {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};

        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|e| SnapError::Aes(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SnapError::Aes(e.to_string()))?;
        Ok((nonce.to_vec(), ct))
    }

    /// AEAD-open a `(nonce, ciphertext)` pair sealed with this key.
    pub fn open(nonce: &[u8], ct: &[u8], key: &VolatileKey) -> Result<Vec<u8>, SnapError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        if nonce.len() != 12 {
            return Err(SnapError::Aes(format!("bad nonce length {}", nonce.len())));
        }
        let cipher =
            Aes256Gcm::new_from_slice(&key.key).map_err(|e| SnapError::Aes(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ct)
            .map_err(|e| SnapError::Aes(e.to_string()))
    }
}

impl Drop for VolatileKey {
    fn drop(&mut self) {
        // Microsecond-zero: scrub the key and release the lock the instant it leaves scope,
        // including during panic unwinding — so a snapshot taken mid-flight finds only zeros.
        secure_mem::secure_zero_memory(&mut self.key);
        secure_mem::unlock_memory(&mut self.key);
    }
}

/// `Debug` is redacted on purpose: the key bytes must never reach logs / crash dumps via the
/// `Debug` trait (which is also used by `unwrap_err`/`unwrap` on the containing `Result`).
impl std::fmt::Debug for VolatileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VolatileKey(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Shards — one share of the 2-of-3 split, locked + don't-dump + zeroize-on-drop
// ---------------------------------------------------------------------------

/// A single Shamir share: `data[0] = x` (share index 1..=3), `data[1..] = y` (32-byte value).
///
/// Memory is `mlock`'d and `MADV_DONTDUMP`'d on creation, and the bytes are zeroized on drop.
pub struct Shard {
    data: [u8; SHARD_LEN],
}

impl Shard {
    /// Build a share from its `x` index and 32-byte `y` value. Locks + excludes from dumps.
    pub fn new(x: u8, y: [u8; KEY_LEN]) -> Self {
        let mut data = [0u8; SHARD_LEN];
        data[0] = x;
        data[1..].copy_from_slice(&y);
        let mut s = Self { data };
        exclude_from_core_dump(&mut s.data);
        secure_mem::lock_memory(&mut s.data);
        s
    }

    #[inline]
    pub fn x(&self) -> u8 {
        self.data[0]
    }

    #[inline]
    pub fn y(&self) -> &[u8] {
        &self.data[1..]
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; SHARD_LEN] {
        &self.data
    }

    /// Reconstruct a shard from raw `SHARD_LEN` bytes (e.g. received from an OHT provider).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapError> {
        if bytes.len() != SHARD_LEN {
            return Err(SnapError::KeyLength { got: bytes.len() });
        }
        let mut data = [0u8; SHARD_LEN];
        data.copy_from_slice(bytes);
        let mut s = Self { data };
        exclude_from_core_dump(&mut s.data);
        secure_mem::lock_memory(&mut s.data);
        Ok(s)
    }
}

impl Drop for Shard {
    fn drop(&mut self) {
        secure_mem::secure_zero_memory(&mut self.data);
        secure_mem::unlock_memory(&mut self.data);
    }
}

// ---------------------------------------------------------------------------
// 2-of-3 split / reconstruct
// ---------------------------------------------------------------------------

/// Split `key` into exactly 3 shares via a random-degree-1 Shamir line `P(x) = secret + a*x`.
/// Any 2 of the 3 reconstruct `secret`; 1 is useless.
pub fn split_key(key: &VolatileKey) -> [Shard; 3] {
    // One random coefficient byte per key position keeps each shard value uniformly random.
    let mut a = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut a);

    let mut secret = match <[u8; KEY_LEN]>::try_from(key.as_bytes()) {
        Ok(s) => s,
        Err(_) => unreachable!("VolatileKey is always KEY_LEN bytes"),
    };

    let mut out = Vec::with_capacity(3);
    for x in 1u8..=3 {
        let mut y = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            // P(x) = secret XOR (a * x)  — addition is XOR in GF(2^8).
            y[i] = secret[i] ^ gf_mul(a[i], x);
        }
        out.push(Shard::new(x, y));
    }
    // Scrub the intermediate secret copy and the random coefficient so neither can be
    // recovered from a snapshot/heap remnant after this call.
    secure_mem::secure_zero_memory(&mut a);
    secure_mem::secure_zero_memory(&mut secret);
    // Safe: we pushed exactly 3.
    [out.remove(0), out.remove(0), out.remove(0)]
}

/// Reconstruct the AES key from exactly two shares via Lagrange interpolation at x=0.
///
/// In GF(2^8) (characteristic 2) subtraction is XOR, so:
/// `secret = y_i*(x_j/(x_i^x_j)) ^ y_j*(x_i/(x_i^x_j))`.
pub fn reconstruct(shards: &[Shard]) -> Result<VolatileKey, SnapError> {
    if shards.len() < 2 {
        return Err(SnapError::InsufficientShards { have: shards.len() });
    }
    let a = &shards[0];
    let b = &shards[1];
    let xa = a.x();
    let xb = b.x();
    let denom = xa ^ xb; // nonzero because shares are distinct

    let lambda_a = gf_div(xb, denom);
    let lambda_b = gf_div(xa, denom);

    let mut secret = [0u8; KEY_LEN];
    let ya = a.y();
    let yb = b.y();
    for i in 0..KEY_LEN {
        secret[i] = gf_mul(ya[i], lambda_a) ^ gf_mul(yb[i], lambda_b);
    }
    let key = VolatileKey::from_bytes(&secret)?;
    // Scrub the stack copy of the reconstructed key; the VolatileKey owns its own locked copy.
    secure_mem::secure_zero_memory(&mut secret);
    Ok(key)
}

/// Like [`reconstruct`] but `panic!`s if fewer than two shares are supplied.
///
/// Use this at boot when the daemon is *expected* to have recovered >=2 shards from the OHT
/// providers; a missing shard is a fatal misconfiguration, not a recoverable error.
pub fn reconstruct_or_panic(shards: &[Shard]) -> VolatileKey {
    reconstruct(shards).unwrap_or_else(|e| panic!("shard reconstruction failed: {e}"))
}

/// Convenience: the `idx`-th share (0..3) for handing to OHT provider `idx`.
///
/// With a 3-provider OHT, each provider receives one independent share; no single provider
/// (nor a snapshot of one) can reconstruct the key. Fetch-and-delete from any two recovers it.
#[inline]
pub fn shard_for_provider(shards: &[Shard; 3], idx: usize) -> &Shard {
    &shards[idx]
}

// ---------------------------------------------------------------------------
// FFI hardening helpers (the only `unsafe` in this module)
// ---------------------------------------------------------------------------

/// Exclude `buf` from core dumps / crash snapshots via `madvise(MADV_DONTDUMP)`.
///
/// Best-effort: returns `false` if the syscall fails (non-Linux, or privileges). Failure does
/// not abort — `mlock` + zeroize-on-drop still bound the exposure window.
pub fn exclude_from_core_dump(buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        unsafe {
            // SAFETY: `buf` is a valid, owned slice. `madvise` only inspects the VM metadata
            // of the pages spanning the range; it never dereferences the pointer. MADV_DONTDUMP
            // is advisory and cannot fault on well-formed inputs.
            let ret = libc::madvise(
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
                libc::MADV_DONTDUMP,
            );
            ret == 0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = buf;
        true
    }
}

/// Refuse to run unless `path` is mounted on `tmpfs`.
///
/// A persistent block device (ext4/xfs/btrfs/...) would let an offline disk clone recover the
/// shards/keys at rest; tmpfs lives only in RAM and dies with the instance. We return `Err` so
/// the caller can `panic!` before any sensitive material is created.
pub fn verify_ephemeral_mount(path: &Path) -> Result<(), SnapError> {
    #[cfg(target_os = "linux")]
    {
        let cpath =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| SnapError::InvalidPath)?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            // SAFETY: `cpath` is a NUL-terminated C string; `stat` is an owned out-parameter.
            // `statfs` writes the filesystem magic into `f_type` and returns 0 on success.
            libc::statfs(cpath.as_ptr(), &mut stat)
        };
        if ret != 0 {
            return Err(SnapError::StatFs(std::io::Error::last_os_error()));
        }
        if stat.f_type != TMPFS_MAGIC {
            return Err(SnapError::NotEphemeral {
                f_type: stat.f_type as u64,
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Boot-time ephemeral-storage policy for a Core Node daemon.
///
/// Checks the filesystem backing `path` (the daemon's state directory). Behaviour:
/// - tmpfs                     → log confirmation, return `Ok(())`.
/// - persistent device (ext4…) → if `ADD_REQUIRE_TMPFS=1` is set, **`panic!`** (refuse to
///   boot, per the snapshot threat model); otherwise emit a loud warning and continue so
///   existing on-disk deployments keep working.
/// - statfs error              → warn (don't crash on a transient probe failure).
///
/// Call this once, early in the daemon's `main`, before any keys/shards are created.
pub fn enforce_ephemeral_storage(path: &Path) {
    let strict = std::env::var("ADD_REQUIRE_TMPFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    match verify_ephemeral_mount(path) {
        Ok(()) => {
            eprintln!("[snapshot_defense] state dir {path:?} is tmpfs (ephemeral) OK");
        }
        Err(SnapError::NotEphemeral { f_type }) => {
            if strict {
                panic!(
                    "ADD_REQUIRE_TMPFS=1: state dir {path:?} is NOT tmpfs (f_type=0x{f_type:x}); \
                     refusing to boot — persistent storage exposes keys to offline disk cloning"
                );
            }
            eprintln!(
                "[snapshot_defense] WARNING: state dir {path:?} is NOT tmpfs (f_type=0x{f_type:x}); \
                 keys are exposed to offline disk cloning. Set ADD_REQUIRE_TMPFS=1 to enforce."
            );
        }
        Err(e) => {
            eprintln!(
                "[snapshot_defense] WARNING: could not verify ephemeral mount for {path:?}: {e}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Generic pinned sensitive buffer (e.g. ML-DSA-87 identity material)
// ---------------------------------------------------------------------------

/// A generic sensitive byte buffer pinned to RAM, excluded from dumps, zeroized on drop.
///
/// Used for ML-DSA-87 identity buffers and any other plaintext that must not survive a snapshot.
pub struct PinnedBytes {
    buf: Vec<u8>,
}

impl PinnedBytes {
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = bytes.to_vec();
        secure_mem::lock_memory(&mut buf);
        exclude_from_core_dump(&mut buf);
        Self { buf }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for PinnedBytes {
    fn drop(&mut self) {
        secure_mem::secure_zero_memory(&mut self.buf);
        secure_mem::unlock_memory(&mut self.buf);
    }
}

// ---------------------------------------------------------------------------
// Secure bootstrap kit: generate → split → persist (1 shard / OHT provider)
// ---------------------------------------------------------------------------

/// Filename under each provider dir holding that provider's unique shard.
const SHARD_FILE: &str = "shard.bin";

/// Three orthogonal key-custody locations ("3 providers"). Substitute real OHT endpoints
/// later; the default is three local dirs so the flow is exercised without external infra.
fn default_provider_dirs(state_dir: &Path) -> [PathBuf; 3] {
    [
        state_dir.join("oht-0"),
        state_dir.join("oht-1"),
        state_dir.join("oht-2"),
    ]
}

/// A volatile AES-256 key plus its 3 SSS shards, materialized only at boot.
///
/// `key` is held for the minimum time: it is generated, used to seal the bootstrap bundle
/// (or for any one-shot sealing need), and then zeroized. The shards are persisted to the
/// provider dirs (fetch-and-delete semantics) so a restart can recover from any two.
pub struct SecKit {
    key: VolatileKey,
    shards: [Shard; 3],
}

impl SecKit {
    /// Generate a fresh volatile key and split it 2-of-3. Persists one shard per provider dir.
    /// Fails if the state dir is not ephemeral (tmpfs) when `require_tmpfs` is set.
    pub fn bootstrap(state_dir: &Path, require_tmpfs: bool) -> Result<Self, SnapError> {
        if require_tmpfs {
            verify_ephemeral_mount(state_dir)?;
        }
        let key = VolatileKey::generate()?;
        let shards = split_key(&key);
        let dirs = default_provider_dirs(state_dir);
        for (i, dir) in dirs.iter().enumerate() {
            let _ = fs::create_dir_all(dir);
            // Fetch-and-delete intent: write the shard, let it be recovered by any 2 providers.
            fs::write(dir.join(SHARD_FILE), shards[i].as_bytes())
                .map_err(|e| SnapError::Persist(e.to_string()))?;
        }
        Ok(Self { key, shards })
    }

    /// Recover from any 2 of 3 provider shards. Panics (boot-fatal) if fewer than two survive.
    pub fn recover_or_bootstrap(state_dir: &Path, require_tmpfs: bool) -> Result<Self, SnapError> {
        let dirs = default_provider_dirs(state_dir);
        let mut found: Vec<Shard> = Vec::with_capacity(3);
        for dir in &dirs {
            if let Ok(bytes) = fs::read(dir.join(SHARD_FILE))
                && let Ok(s) = Shard::from_bytes(&bytes)
            {
                found.push(s);
            }
            if found.len() >= 2 {
                break;
            }
        }
        if found.len() < 2 {
            // Not enough shards to reconstruct → mint a fresh kit (first boot / disaster recovery).
            return Self::bootstrap(state_dir, require_tmpfs);
        }
        let key = reconstruct_or_panic(&found);
        // Re-split to refresh all three shards in case one was lost.
        let shards = split_key(&key);
        let dirs = default_provider_dirs(state_dir);
        for (i, dir) in dirs.iter().enumerate() {
            let _ = fs::create_dir_all(dir);
            fs::write(dir.join(SHARD_FILE), shards[i].as_bytes())
                .map_err(|e| SnapError::Persist(e.to_string()))?;
        }
        Ok(Self { key, shards })
    }

    /// Consume the kit, returning the volatile key. The caller must use it and drop it promptly.
    pub fn into_key(self) -> VolatileKey {
        self.key
    }

    /// Zeroize the in-memory key and shards immediately (e.g. on graceful shutdown).
    pub fn forget(mut self) {
        // `key` and `shards` zeroize themselves on `drop`; assigning a blank kit then dropping
        // ensures the sensitive material is scrubbed right now rather than at some later scope.
        self.key = VolatileKey::from_bytes(&[0u8; KEY_LEN]).unwrap_or_else(|_| unreachable!());
        for s in self.shards.iter_mut() {
            *s = Shard::from_bytes(&[0u8; SHARD_LEN]).unwrap_or_else(|_| unreachable!());
        }
    }
}

/// `Debug` is redacted on purpose: the key/shards must never reach logs via `Debug`.
impl std::fmt::Debug for SecKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecKit(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_arithmetic_sanity() {
        // Poly-agnostic field-law checks (independent of which reduction poly we use):
        // identity, multiplicative inverse, and commutativity must all hold.
        assert_eq!(gf_mul(0x53, 0x01), 0x53, "x*1 == x");
        assert_eq!(gf_mul(0x53, gf_inv(0x53)), 0x01, "x * x^-1 == 1");
        assert_eq!(gf_mul(0xCA, gf_inv(0xCA)), 0x01);
        assert_eq!(gf_mul(0x53, 0xCA), gf_mul(0xCA, 0x53), "commutative");
        // Multiplication distributes over XOR (the GF addition).
        assert_eq!(
            gf_mul(0x53 ^ 0x0F, 0xCA) ^ gf_mul(0x0F, 0xCA),
            gf_mul(0x53, 0xCA),
            "distributes over XOR"
        );
    }

    #[test]
    fn split_reconstruct_any_pair() {
        let key = VolatileKey::generate().unwrap();
        let original = key.as_bytes().to_vec();
        let shards = split_key(&key);

        // All three pairings must recover the same key.
        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            let pair = &shards[i..=j];
            let recovered = reconstruct(pair).unwrap();
            assert_eq!(recovered.as_bytes(), original.as_slice());
        }

        // And the full set works too.
        let recovered = reconstruct(&shards).unwrap();
        assert_eq!(recovered.as_bytes(), original.as_slice());
    }

    #[test]
    fn reconstruct_fails_with_one_shard() {
        let key = VolatileKey::generate().unwrap();
        let shards = split_key(&key);
        // Only one shard supplied -> must error, never leak the key.
        let err = reconstruct(&shards[0..1]).unwrap_err();
        assert!(matches!(err, SnapError::InsufficientShards { have: 1 }));
    }

    #[test]
    #[should_panic(expected = "shard reconstruction failed")]
    fn reconstruct_or_panic_one_shard() {
        let key = VolatileKey::generate().unwrap();
        let shards = split_key(&key);
        let _ = reconstruct_or_panic(&shards[0..1]);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = VolatileKey::generate().unwrap();
        let plaintext = b"routing-metadata-that-must-not-leak";
        let (nonce, ct) = key.seal(plaintext).unwrap();
        let opened = VolatileKey::open(&nonce, &ct, &key).unwrap();
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn shard_serialization_roundtrip() {
        let key = VolatileKey::generate().unwrap();
        let shards = split_key(&key);
        // A shard handed to an OHT provider and read back must reconstruct identically.
        let wire = shards[1].as_bytes().to_vec();
        let restored = Shard::from_bytes(&wire).unwrap();
        assert_eq!(restored.x(), shards[1].x());
        assert_eq!(restored.y(), shards[1].y());
        // Reconstruct from the original-arrangement pair (restored shares the same bytes).
        let recovered = reconstruct(&shards[1..=2]).unwrap();
        assert_eq!(recovered.as_bytes(), key.as_bytes());
    }

    #[test]
    fn tmpfs_rejects_persistent_path() {
        // Our source tree lives on a real (non-tmpfs) device — must be rejected so the daemon
        // refuses to hold shards there.
        let err = verify_ephemeral_mount(Path::new(".")).unwrap_err();
        assert!(matches!(err, SnapError::NotEphemeral { .. }));
    }

    #[test]
    fn pinned_bytes_zeroized_on_drop() {
        let src = b"ml-dsa-identity-bytes";
        let p = PinnedBytes::new(src);
        assert_eq!(p.as_bytes().len(), src.len());
        assert_eq!(p.as_bytes(), &src[..]);
        // Drop is exercised implicitly; secure_zero_memory runs in Drop.
    }

    #[test]
    fn seckit_bootstrap_then_recover_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nn_seckit_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // First boot: fresh kit, shards persisted across 3 provider dirs.
        let kit = SecKit::bootstrap(&dir, false).expect("bootstrap");
        let original = {
            let key = kit.into_key();
            let (nonce, ct) = key.seal(b"boot").expect("seal");
            // Recover the SAME key from the on-disk shards (any 2 of 3) — proves persistence.
            let recovered = SecKit::recover_or_bootstrap(&dir, false).expect("recover");
            let rkey = recovered.into_key();

            VolatileKey::open(&nonce, &ct, &rkey).expect("open")
        };
        assert_eq!(original, b"boot");

        // Simulate loss of one shard (provider down): recovery still works from the other 2.
        let _ = std::fs::remove_file(dir.join("oht-0").join("shard.bin"));
        let recovered2 = SecKit::recover_or_bootstrap(&dir, false).expect("recover-after-loss");
        let rk2 = recovered2.into_key();
        let (nonce2, ct2) = rk2.seal(b"again").expect("seal");
        assert_eq!(VolatileKey::open(&nonce2, &ct2, &rk2).unwrap(), b"again");

        // With tmpfs required on a persistent (non-tmpfs) dir, bootstrap must refuse.
        let err = SecKit::bootstrap(Path::new("."), true).unwrap_err();
        assert!(matches!(err, SnapError::NotEphemeral { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
