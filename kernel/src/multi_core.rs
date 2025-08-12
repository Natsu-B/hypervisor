// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! MultiCore Handling Functions
//!

use core::{arch::global_asm, panic};

use alloc::alloc::Layout;
use alloc::alloc::alloc;
use common::{
    cpu::{self, convert_virtual_address_to_physical_address_el2_read, secure_monitor_call},
    println,
};

use crate::{STACK_PAGES, exception::Registers, paging::PAGE_SHIFT};

unsafe extern "C" {
    fn app_cpu_boot();
}

pub fn setup_new_cpu(regs: &mut Registers) {
    println!("set up new cpu...");
    let stack_layout = Layout::from_size_align(STACK_PAGES << PAGE_SHIFT, 8).unwrap();
    let mut stack_addr = unsafe { alloc(stack_layout) } as usize;
    stack_addr -= STACK_PAGES;
    let app_start_addr =
        convert_virtual_address_to_physical_address_el2_read(app_cpu_boot as *const fn() as usize)
            .unwrap() as u64;
    cpu::dsb();
    cpu::clean_data_cache_all();
    let result = call_psci_function(0xC400_0003, regs.x1, app_start_addr, stack_addr as u64);
    if result != 0 {
        panic!("failed to call psci: {:#?}", result);
    }
}

pub fn call_psci_function(function_id: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let mut regs: Registers = Default::default();
    regs.x0 = function_id;
    regs.x1 = arg0;
    regs.x2 = arg1;
    regs.x3 = arg2;
    secure_monitor_call(
        &mut regs.x0,
        &mut regs.x1,
        &mut regs.x2,
        &mut regs.x3,
        &mut regs.x4,
        &mut regs.x5,
        &mut regs.x6,
        &mut regs.x7,
        &mut regs.x8,
        &mut regs.x9,
        &mut regs.x10,
        &mut regs.x11,
        &mut regs.x12,
        &mut regs.x13,
        &mut regs.x14,
        &mut regs.x15,
        &mut regs.x16,
        &mut regs.x17,
    );
    regs.x0
}

#[unsafe(no_mangle)]
extern "C" fn app_main() {
    println!("hello app main!!!");
    todo!();
}

global_asm!(
    r#"
.global app_cpu_boot
.section ".text.boot"

app_cpu_boot:
    mov sp, x0
    b app_main
loop:
    wfe
    b loop
    "#
);
