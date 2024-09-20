// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! MultiCore Handling Functions
//!

use common::cpu::PAGE_SIZE;

pub fn init_spin_table(address:usize, length:usize){
    let aligned_base_address = if base_address == 0 {
        0
    } else {
        (base_address - 1) & !(PAGE_SIZE - 1)
    };
    let aligned_length =
        ((length + (base_address - aligned_base_address) - 1) & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    map_address(
        aligned_base_address,
        aligned_base_address,
        aligned_length,
        true,
        true,
        false,
        true,
    )
    .expect("Failed to map spin table");
    add_memory_access_trap(aligned_base_address, aligned_length, true, false)
        .expect("Failed to add trap of spin table");
    add_memory_store_access_handler(StoreAccessHandlerEntry::new(
        base_address,
        length,
        0,
        spin_table_store_access_handler,
    ))
    .expect("Failed to add store access handler");
}