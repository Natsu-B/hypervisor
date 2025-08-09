// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Console with UEFI Output Protocol
//!

use crate::SERIAL_PORT;
use crate::uefi::{EfiStatus, output::EfiOutputProtocol};

use core::fmt;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use mutex::SpinLock;

pub struct Console {
    uefi_output_console: MaybeUninit<&'static EfiOutputProtocol>,
    //write_lock: SpinLockFlag, // Currently, Bootloader runs only BSP. Therefore the lock is not necessary.
}

pub static mut DEFAULT_CONSOLE: SpinLock<Console> = SpinLock::new(Console::new());

impl Console {
    pub const fn new() -> Self {
        Self {
            uefi_output_console: MaybeUninit::uninit(),
        }
    }

    pub fn init(&mut self, efi_output_protocol: *const EfiOutputProtocol) {
        self.uefi_output_console = MaybeUninit::new(unsafe { &*efi_output_protocol });
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, string: &str) -> fmt::Result {
        if let Some(serial_port) = unsafe { SERIAL_PORT } {
            crate::print::put_unsafe(string, serial_port);
            Ok(())
        } else {
            let result = unsafe { self.uefi_output_console.assume_init().output(string) };
            if result == EfiStatus::EfiSuccess {
                Ok(())
            } else {
                Err(fmt::Error)
            }
        }
    }
}

pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    let mut lock = unsafe { (*(&raw mut DEFAULT_CONSOLE)).lock() };
    let result = lock.deref_mut().write_fmt(args);
    if result.is_err() {
        panic!("write_fmt was failed.");
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => ($crate::console::print(format_args!("{}\n", format_args!($fmt))));
    ($fmt:expr, $($arg:tt)*) => ($crate::console::print(format_args!("{}\n", format_args!($fmt, $($arg)*))));
}

#[macro_export]
macro_rules! pr_debug {
    ($fmt:expr) => (println!($fmt));
    ($fmt:expr, $($arg:tt)*) => (println!($fmt, $($arg)*));
}
