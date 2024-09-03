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

use core::option::Option;
use core::num::NonZeroUsize;

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