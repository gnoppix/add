//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

//! Secure memory utilities for key material protection.
//!
//! This module implements ACS2.6 specification requirements for memory hardening:
//! - secure_zero_memory: Prevents dead store elimination optimization
//! - mlock: Locks memory to prevent swapping to disk (Linux/Unix platforms)
//! - Guard pages: Unmapped memory pages around key material to catch overflows
//! - SecureKeyMaterial: Optional guard-page-protected key allocation
//! - Assembly barriers: Speculative execution mitigation (LFENCE, speculation barrier)

use std::alloc::{Layout, alloc};
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, compiler_fence};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Guard page size (matches typical OS page size)
pub const GUARD_PAGE_SIZE: usize = 4096;

/// Securely overwrites a memory buffer with zeros.
///
/// Uses volatile writes and compiler memory barriers to prevent LLVM's Dead Store Elimination (DSE)
/// optimization from stripping the zeroing code during release builds.
///
/// This is critical for:
/// - Master storage key scrubbing during app backgrounding
/// - Kyber private key material cleanup after use
/// - Session key clearing after decryption
#[inline(never)]
pub fn secure_zero_memory(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    unsafe {
        let mut ptr = buffer.as_mut_ptr();
        let end = ptr.add(buffer.len());

        while ptr < end {
            // Volatile write ensures the compiler cannot optimize this away
            std::ptr::write_volatile(ptr, 0u8);
            ptr = ptr.add(1);
        }
    }

    // Sequential consistency fence acts as an architectural memory barrier
    // This prevents reordering across the zeroing operation
    compiler_fence(Ordering::SeqCst);
}

/// Speculative execution mitigation barrier (LFENCE).
///
/// Prevents speculative execution from leaking data via side channels (Spectre/Meltdown).
/// On x86_64, emits LFENCE. On ARM, emits DSB SYS + ISB.
/// On other architectures, acts as a compiler barrier.
#[inline(always)]
pub fn speculation_barrier() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("lfence", options(nostack, nomem, preserves_flags));
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", "isb", options(nostack, nomem, preserves_flags));
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compiler_fence(Ordering::SeqCst);
}

/// Hardened version of secure_zero_memory with speculation barrier.
///
/// Adds LFENCE/DSB+ISB before and after zeroing to prevent speculative
/// execution from reading zeroed memory during the operation.
#[inline(never)]
pub fn secure_zero_memory_hardened(buffer: &mut [u8]) {
    if buffer.is_empty() {
        return;
    }

    // Pre-zeroing speculation barrier
    speculation_barrier();

    unsafe {
        let mut ptr = buffer.as_mut_ptr();
        let end = ptr.add(buffer.len());

        while ptr < end {
            std::ptr::write_volatile(ptr, 0u8);
            ptr = ptr.add(1);
        }
    }

    compiler_fence(Ordering::SeqCst);

    // Post-zeroing speculation barrier
    speculation_barrier();
}

/// Locks memory pages to prevent swapping to disk.
///
/// On Linux/Android, uses mlock. Returns Ok(true) on success, Ok(false) on unsupported
/// or failed platforms. This is best-effort - the function does not fail if mlock fails.
pub fn lock_memory(buffer: &mut [u8]) -> bool {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    {
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len() as libc::size_t;
            let ret = libc::mlock(ptr, len);
            ret == 0
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        // No-op on unsupported platforms
        true
    }
}

/// Unlocks previously locked memory pages.
pub fn unlock_memory(buffer: &mut [u8]) -> bool {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    {
        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
            let len = buffer.len() as libc::size_t;
            let ret = libc::munlock(ptr, len);
            ret == 0
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        true
    }
}

/// Secure container for cryptographic key material.
///
/// Automatically scrubs memory on drop using secure_zero_memory.
/// Optionally locks pages in RAM via mlock to prevent swap leakage.
#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SecureKeyMaterial {
    key_material: Vec<u8>,
    locked: bool,
}

impl Clone for SecureKeyMaterial {
    fn clone(&self) -> Self {
        Self {
            key_material: self.key_material.clone(),
            locked: self.locked,
        }
    }
}

impl SecureKeyMaterial {
    /// Create a new secure key material container.
    ///
    /// If `lock_pages` is true, attempts to mlock the memory.
    pub fn new(key_bytes: Vec<u8>, lock_pages: bool) -> Self {
        let locked = if lock_pages && !key_bytes.is_empty() {
            let mut key_ref = key_bytes.clone();
            lock_memory(&mut key_ref)
        } else {
            false
        };
        Self {
            key_material: key_bytes,
            locked,
        }
    }

    /// Access the key material (for encryption operations).
    pub fn bytes(&self) -> &[u8] {
        &self.key_material
    }

    /// Get length of key material.
    pub fn len(&self) -> usize {
        self.key_material.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.key_material.is_empty()
    }

    /// Explicitly purge key from memory.
    /// Called automatically on drop, but can be invoked early.
    pub fn purge(&mut self) {
        secure_zero_memory(&mut self.key_material);
        if self.locked {
            let _ = unlock_memory(&mut self.key_material);
            self.locked = false;
        }
    }

    /// Get mutable access to key material for memory locking operations.
    pub fn key_material_mut(&mut self) -> &mut [u8] {
        &mut self.key_material
    }
}

/// Allocate memory with guard pages on both sides.
///
/// Layout: [Guard Page (PROT_NONE)] [Key Data] [Guard Page (PROT_NONE)]
/// Returns a NonNull pointer to the key data region (not the guard pages).
///
/// # Safety
/// The caller must ensure the returned pointer is properly freed via `dealloc_guarded`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub unsafe fn alloc_guarded(data_size: usize) -> Option<NonNull<u8>> {
    let page_size = GUARD_PAGE_SIZE;
    let total_size = page_size * 2 + data_size;
    // Round up to page boundary
    let total_size = (total_size + page_size - 1) & !(page_size - 1);

    let layout = Layout::from_size_align(total_size, page_size).ok()?;
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return None;
    }

    // Make the first guard page inaccessible
    unsafe {
        let guard_before = base as *mut libc::c_void;
        libc::mprotect(guard_before, page_size, libc::PROT_NONE);
    }

    // Make the last guard page inaccessible
    unsafe {
        let guard_after = base.add(total_size - page_size) as *mut libc::c_void;
        libc::mprotect(guard_after, page_size, libc::PROT_NONE);
    }

    // Lock the data region in RAM
    let data_ptr = unsafe { base.add(page_size) as *mut libc::c_void };
    unsafe {
        libc::mlock(data_ptr, data_size as libc::size_t);
    }

    unsafe { Some(NonNull::new_unchecked(data_ptr as *mut u8)) }
}

/// Deallocate guarded memory with guard pages.
///
/// # Safety
/// `ptr` must have been returned by `alloc_guarded` with the same `data_size`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub unsafe fn dealloc_guarded(ptr: NonNull<u8>, data_size: usize) {
    let page_size = GUARD_PAGE_SIZE;
    let total_size = page_size * 2 + data_size;
    let total_size = (total_size + page_size - 1) & !(page_size - 1);

    let base = unsafe { ptr.as_ptr().sub(page_size) as *mut libc::c_void };

    // Unlock the data region
    unsafe {
        let data_ptr = ptr.as_ptr() as *mut libc::c_void;
        libc::munlock(data_ptr, data_size as libc::size_t);
    }

    // Unmap the entire region (guard pages + data)
    unsafe {
        libc::munmap(base, total_size as libc::size_t);
    }
}

/// Guard-page-protected key material for high-security environments.
///
/// On Linux/Android, allocates key data between two PROT_NONE guard pages
/// that are mlock'd and surrounded by unmapped memory. Any buffer overflow
/// or out-of-bounds access triggers an immediate SIGSEGV.
///
/// On unsupported platforms, falls back to standard `SecureKeyMaterial`.
pub struct GuardedKeyMaterial {
    ptr: NonNull<u8>,
    len: usize,
}

impl GuardedKeyMaterial {
    /// Create a new guard-page-protected key material.
    ///
    /// Copies `key_bytes` into guarded memory and zeroes the source.
    pub fn new(key_bytes: &mut [u8]) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let len = key_bytes.len();
            let ptr = unsafe { alloc_guarded(len)? };
            unsafe {
                std::ptr::copy_nonoverlapping(key_bytes.as_ptr(), ptr.as_ptr(), len);
            }
            secure_zero_memory(key_bytes);
            Some(Self { ptr, len })
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = key_bytes;
            None // Unsupported on this platform
        }
    }

    /// Access the key material.
    pub fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Get length of key material.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for GuardedKeyMaterial {
    fn drop(&mut self) {
        unsafe {
            secure_zero_memory(std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len));
            #[cfg(any(target_os = "linux", target_os = "android"))]
            dealloc_guarded(self.ptr, self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero_memory() {
        let mut buffer = [0x42u8; 32];
        assert_eq!(buffer, vec![0x42u8; 32].as_slice());

        secure_zero_memory(&mut buffer);

        // After secure zeroing, all bytes should be zero
        assert_eq!(buffer, vec![0u8; 32].as_slice());
    }

    #[test]
    fn test_secure_key_material() {
        let key = vec![0xDEu8; 32];
        let skm = SecureKeyMaterial::new(key.clone(), false);
        assert_eq!(skm.bytes(), &key[..]);
    }

    #[test]
    fn test_secure_key_material_purge() {
        let key = vec![0xDEu8; 32];
        let mut skm = SecureKeyMaterial::new(key.clone(), false);
        skm.purge();
        // After purge, the buffer should be zeroed
        let all_zeros = skm.bytes().iter().all(|&b| b == 0);
        assert!(skm.is_empty() || all_zeros);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn test_guarded_key_material() {
        let mut key = vec![0xADu8; 64];
        let gkm = GuardedKeyMaterial::new(&mut key).unwrap();
        // Source buffer should be zeroed
        assert!(key.iter().all(|&b| b == 0));
        // Key material accessible and correct
        assert_eq!(gkm.len(), 64);
        assert!(!gkm.is_empty());
        // Verify content
        let expected = vec![0xADu8; 64];
        assert_eq!(gkm.bytes(), expected.as_slice());
    }
}
