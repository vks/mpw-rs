extern crate crypto;

use std::convert::AsMut;
use std::ops::Deref;

use self::crypto::util::secure_memset;

pub trait UnsafeAsMut {
    unsafe fn as_mut(&mut self) -> &mut [u8];
}

/*
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
#[derive(Debug)]
pub struct ClearOnDrop<T: UnsafeAsMut> {
    pub container: T
}

impl<T: UnsafeAsMut> ClearOnDrop<T> {
    pub fn new(container: T) -> ClearOnDrop<T> {
        ClearOnDrop { container: container }
    }
}

impl<T: UnsafeAsMut> Deref for ClearOnDrop<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.container
    }
}

impl<T: UnsafeAsMut> Drop for ClearOnDrop<T> {
    fn drop(&mut self) {
        secure_memset(unsafe { self.container.as_mut() }, 0);
    }
}

#[test]
fn test_clear_on_drop_string() {
    let s = "hello".to_string();
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

