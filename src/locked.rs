use zeroize::Zeroize as _;

const LEN: usize = 4096;

#[cfg(unix)]
static MLOCK_WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// RAII guard around `mlock`/`munlock`. `munlock` can spuriously fail with
/// `ENOMEM` on musl under `RLIMIT_MEMLOCK` pressure (common in CI
/// containers); pages are released on process exit anyway, so unlock is
/// best-effort and never panics on drop.
#[cfg(unix)]
struct MlockGuard {
    ptr: *mut core::ffi::c_void,
    len: usize,
}

// The guard only tracks an address + length owned for the lifetime of the
// owning `FixedVec`; safe to move across threads.
#[cfg(unix)]
unsafe impl Send for MlockGuard {}
#[cfg(unix)]
unsafe impl Sync for MlockGuard {}

#[cfg(unix)]
impl Drop for MlockGuard {
    fn drop(&mut self) {
        // SAFETY: (ptr, len) came from a successful `mlock` call on a
        // `Box<FixedVec>` that is still live (guard is dropped before the
        // box).
        let _ = unsafe { rustix::mm::munlock(self.ptr, self.len) };
    }
}

#[cfg(unix)]
fn try_mlock(ptr: *const u8, len: usize) -> rustix::io::Result<MlockGuard> {
    // rustix takes *mut c_void to match the POSIX signature, even though
    // mlock doesn't mutate.
    let p = ptr.cast::<core::ffi::c_void>().cast_mut();
    // SAFETY: `ptr` points to a live allocation of at least `len` bytes
    // owned by the caller.
    unsafe { rustix::mm::mlock(p, len) }?;
    Ok(MlockGuard { ptr: p, len })
}

#[cfg(windows)]
static MLOCK_WORKS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

#[cfg(windows)]
struct MlockGuard {
    ptr: *mut core::ffi::c_void,
    len: usize,
}

#[cfg(windows)]
unsafe impl Send for MlockGuard {}
#[cfg(windows)]
unsafe impl Sync for MlockGuard {}

#[cfg(windows)]
impl Drop for MlockGuard {
    fn drop(&mut self) {
        // SAFETY: (ptr, len) came from a successful VirtualLock on a live
        // allocation; VirtualUnlock is best-effort and pages are released
        // on process exit anyway.
        unsafe {
            let _ = windows_sys::Win32::System::Memory::VirtualUnlock(
                self.ptr, self.len,
            );
        }
    }
}

#[cfg(windows)]
fn try_mlock(
    ptr: *const u8,
    len: usize,
) -> std::io::Result<MlockGuard> {
    let p = ptr.cast::<core::ffi::c_void>().cast_mut();
    // SAFETY: `ptr` points to a live allocation of at least `len` bytes
    // owned by the caller.
    let ok = unsafe {
        windows_sys::Win32::System::Memory::VirtualLock(p, len)
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(MlockGuard { ptr: p, len })
}

pub struct FixedVec<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> FixedVec<N> {
    fn new() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
        }
    }

    const fn capacity() -> usize {
        N
    }

    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn extend(&mut self, it: impl Iterator<Item = u8>) {
        for b in it {
            assert!(self.len < N, "FixedVec capacity exceeded");
            self.data[self.len] = b;
            self.len += 1;
        }
    }
}

impl<const N: usize> Drop for FixedVec<N> {
    fn drop(&mut self) {
        self.data[..self.len].zeroize();
    }
}

pub struct Vec {
    data: Box<FixedVec<LEN>>,
    _lock: Option<MlockGuard>,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(FixedVec::<LEN>::new());
        #[cfg(unix)]
        let lock = match MLOCK_WORKS.get() {
            Some(true) => {
                try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity()).ok()
            }
            Some(false) => None,
            None => {
                match try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity()) {
                    Ok(lock) => {
                        let _ = MLOCK_WORKS.set(true);
                        Some(lock)
                    }
                    Err(e) => {
                        if MLOCK_WORKS.set(false).is_ok() {
                            eprintln!("failed to lock memory region: {e}");
                        }
                        None
                    }
                }
            }
        };
        #[cfg(windows)]
        let lock = match MLOCK_WORKS.get() {
            Some(true) => {
                try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity()).ok()
            }
            Some(false) => None,
            None => {
                match try_mlock(data.as_ptr(), FixedVec::<LEN>::capacity()) {
                    Ok(lock) => {
                        let _ = MLOCK_WORKS.set(true);
                        Some(lock)
                    }
                    Err(e) => {
                        if MLOCK_WORKS.set(false).is_ok() {
                            eprintln!("failed to lock memory region: {e}");
                        }
                        None
                    }
                }
            }
        };
        Self { data, _lock: lock }
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat_n(0, LEN));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.zero();
        self.data.as_mut_slice().zeroize();
    }
}

impl Clone for Vec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }

    /// Full 64-byte `enc_key` || `mac_key` buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.keys.data()[0..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}

#[cfg(test)]
mod tests {
    use super::FixedVec;

    #[test]
    fn push_len_and_slice() {
        let mut v = FixedVec::<8>::new();
        v.extend([1u8, 2, 3, 4].into_iter());
        assert_eq!(v.as_slice().len(), 4);
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn truncate_and_clear() {
        let mut v = FixedVec::<8>::new();
        v.extend([1u8, 2, 3, 4].into_iter());
        v.truncate(0);
        assert!(v.as_slice().is_empty());
        assert_eq!(v.data[..4], [1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "FixedVec capacity exceeded")]
    fn push_past_capacity_panics() {
        let mut v = FixedVec::<2>::new();
        v.extend([1u8, 2, 3].into_iter());
    }

    #[test]
    fn fixed_vec_drop_zeros_written_bytes() {
        // FixedVec::Drop must zeroize the written region. The memory cannot
        // be observed after drop, so the Drop body's zeroize call is invoked
        // manually here and the internal `data` array is checked.
        let mut v = FixedVec::<8>::new();
        v.extend([0xaa_u8, 0xbb, 0xcc, 0xdd].into_iter());
        assert_eq!(v.data[..4], [0xaa, 0xbb, 0xcc, 0xdd]);
        {
            use zeroize::Zeroize as _;
            v.data[..v.len].zeroize();
        }
        assert_eq!(v.data[..4], [0, 0, 0, 0]);
    }

    #[test]
    fn locked_vec_extend_and_data() {
        let mut v = super::Vec::new();
        v.extend([1_u8, 2, 3, 4].iter().copied());
        assert_eq!(v.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn locked_vec_zero_fills_and_exposes_full_slice() {
        let mut v = super::Vec::new();
        v.extend([9_u8; 16].iter().copied());
        v.zero();
        // After zero(), the logical slice covers full capacity and reads
        // as all zeros; previous contents must not be visible.
        assert_eq!(v.data().len(), super::LEN);
        assert!(v.data().iter().all(|b| *b == 0));
    }

    #[test]
    fn locked_vec_truncate_shrinks_visible_slice() {
        let mut v = super::Vec::new();
        v.extend((0_u8..32).chain(std::iter::repeat_n(0, 0)));
        assert_eq!(v.data().len(), 32);
        v.truncate(8);
        assert_eq!(v.data(), &(0_u8..8).collect::<std::vec::Vec<_>>()[..]);
    }

    #[test]
    fn locked_vec_clone_is_independent() {
        let mut original = super::Vec::new();
        original.extend([1_u8, 2, 3, 4].iter().copied());
        let copy = original.clone();
        assert_eq!(copy.data(), &[1, 2, 3, 4]);
        original.data_mut()[0] = 99;
        assert_eq!(copy.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn keys_exposes_enc_mac_split() {
        let mut buf = super::Vec::new();
        buf.extend((0_u8..64).collect::<std::vec::Vec<_>>().into_iter());
        let k = super::Keys::new(buf);
        assert_eq!(k.enc_key().len(), 32);
        assert_eq!(k.mac_key().len(), 32);
        assert_eq!(k.as_bytes().len(), 64);
        assert_eq!(k.enc_key()[0], 0);
        assert_eq!(k.enc_key()[31], 31);
        assert_eq!(k.mac_key()[0], 32);
        assert_eq!(k.mac_key()[31], 63);
    }
}
