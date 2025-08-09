#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

// 基本的に単コアのみで動作を前提としている

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    // TODO critical section (no interrupt?)
    pub fn lock(&'_ self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}
#[cfg(test)]
mod tests {
    use core_affinity::CoreId;

    use super::*;
    extern crate core_affinity;
    use core::time::Duration;
    use std::sync::Arc;
    use std::thread;
    fn get_core_id() -> CoreId {
        let mut core_ids = core_affinity::get_core_ids().unwrap();
        core_ids.pop().unwrap()
    }
    #[test]
    fn spinlock_test() {
        let core_id = get_core_id();
        let test_data: Arc<SpinLock<usize>> = Arc::new(SpinLock::new(0));

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let test_data_clone = Arc::clone(&test_data);
                thread::spawn(move || {
                    if core_affinity::set_for_current(core_id) {
                        for _ in 0..1000 {
                            let arc = test_data_clone.lock().lock;
                            let mut arc = arc.lock();
                            let data = arc.deref_mut();
                            *data += 1;
                        }
                    }
                })
            })
            .collect();

        for handle in handles.into_iter() {
            handle.join().unwrap();
        }
        assert_eq!(*test_data.lock().deref(), 100 * 1000);
    }
}
