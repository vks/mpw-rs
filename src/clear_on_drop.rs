extern crate libc;
extern crate errno;

use std::convert::AsMut;
use std::ops::{Deref, DerefMut};
use std::intrinsics;

use self::libc::c_void;
use self::errno::{errno, Errno};

#[derive(Debug, Clone, Copy)]
enum Error {
    /// Some of the specified address range does not correspond to mapped pages
    /// in the address space of the process.
    NoMemory,
    /// The caller is not privileged, but needs privilege to perform the
    /// requested operation.
    Permission,
    /// Some or all of the specified address range could not be locked.
    Again,
    /// Address was not a multiple of the page size (not on Linux).
    Invalid,
    /// Other, unexpected error.
    Other(Errno),
}

impl From<Errno> for Error {
    fn from(errno: Errno) -> Error {
        let Errno(error_code) = errno;
        match error_code {
            libc::ENOMEM => Error::NoMemory,
            libc::EPERM => Error::Permission,
            libc::EAGAIN => Error::Again,
            libc::EINVAL => Error::Invalid,
            _ => Error::Other(errno),
        }
    }
}

/// Lock part of the calling process's virtual memory into RAM.
///
/// This prevents that memory from being paged to the swap area.
fn mlock(slice: &[u8]) -> Result<(), Error> {
    let return_code = unsafe {
        libc::mlock(slice.as_ptr() as *const c_void, slice.len())
    };
    if return_code == 0 {
        return Ok(());
    }
    Err(errno().into())
}

/// Unlock pages in the given address range.
///
/// After this call, all pages that contain a part of the specified memory
/// range can be moved to external swap space again by the kernel.
fn munlock(slice: &[u8]) -> Result<(), Error> {
    let return_code = unsafe {
        libc::munlock(slice.as_ptr() as *const c_void, slice.len())
    };
    if return_code == 0 {
        return Ok(());
    }
    Err(errno().into())
}

/// A cheap, mutable reference-to-mutable reference conversion.
///
/// Because it is implemented for String as well, it is unsafe to call.
/// (It allows violating memory safety by setting a non-UTF-8 string.)
pub trait UnsafeAsMut {
    unsafe fn as_mut(&mut self) -> &mut [u8];
}

/* Ideally this should be used, but it conflicts with the implementation for String.
 * Furthermore, AsMut is not implemented for [u8; 64].

impl<T: AsMut<[u8]>> UnsafeAsMut for T {
    unsafe fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}
*/

impl UnsafeAsMut for Vec<u8> {
    unsafe fn as_mut(&mut self) -> &mut [u8] {
        AsMut::as_mut(self)
    }
}

impl UnsafeAsMut for [u8; 64] {
    unsafe fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl UnsafeAsMut for String {
    unsafe fn as_mut(&mut self) -> &mut [u8] {
        AsMut::as_mut(self.as_mut_vec())
    }
}

/// A container representing a byte slice that is set to zero on drop.
///
/// Useful to make sure that secret data is cleared from memory after use.
// TODO: Investigate mprotect.
#[derive(Debug)]
pub struct ClearOnDrop<T: UnsafeAsMut> {
    container: Box<T>
}

impl<T: UnsafeAsMut> ClearOnDrop<T> {
    pub fn new(container: T) -> ClearOnDrop<T> {
        // Make sure the string is not swapped by using mlock.
        let mut result = ClearOnDrop { container: Box::new(container) };
        unsafe {
            let slice = result.container.deref_mut().as_mut();
            let _ = mlock(slice);  // This sometimes fails for some reason.
        }
        result
    }
}

impl<T: UnsafeAsMut> Deref for ClearOnDrop<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.container
    }
}

impl<T: UnsafeAsMut> DerefMut for ClearOnDrop<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.container
    }
}

impl<T: UnsafeAsMut> Drop for ClearOnDrop<T> {
    #[inline(never)]
    fn drop(&mut self) {
        // We use a volatile memset that makes sure it is not optimized away. It
        // is safe to overwrite strings with zeros, because it is valid UTF-8.
        unsafe {
            let slice = self.container.deref_mut().as_mut();
            intrinsics::volatile_set_memory(slice.as_ptr() as *mut c_void, 0, slice.len());
            let _ = munlock(slice);  // This sometimes fails for some reason.
        }
    }
}

#[test]
fn test_clear_on_drop_string() {
    let s: String = "hello".to_string();
    let _ = ClearOnDrop::new(s);
}

#[test]
fn test_clear_on_drop_vec() {
    let v: Vec<u8> = b"hello".to_vec();
    let _ = ClearOnDrop::new(v);
}

#[test]
fn test_clear_on_drop_array() {
    let a = [1; 64];
    let _ = ClearOnDrop::new(a);
}
