// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]

pub mod uefi;
pub mod console;
pub mod cpu;
pub mod print;

use core::option::Option;
use core::num::NonZeroUsize;

pub static mut SERIAL_PORT:Option<usize> = None; //:warning: This will changed by other program!!!
pub const PL011_QEMU: usize = 0x900_0000; //for qm
//const PL011: usize = 0x107D001000;//for raspi 5
pub const RANGE: usize = 0x1000;

pub const UART_DR: usize = 0x000;
pub const UART_FR: usize = 0x018;

#[macro_export]
macro_rules! bitmask {
    ($high:expr,$low:expr) => {
        ((1 << (($high - $low) + 1)) - 1) << $low
    };
}

pub struct SystemInformation {
    pub spin_table_info: Option<(
        usize,
        NonZeroUsize,
)>,
    pub serial_port: Option<usize>,
}