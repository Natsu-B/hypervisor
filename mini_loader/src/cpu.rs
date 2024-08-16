// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! CPU Specified Assembly functions
//!

use core::arch::asm;

/* TCR_EL2 */
pub const TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H: u64 = 32;
pub const TCR_EL2_DS_WITHOUT_E2H: u64 = 1 << TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H: u64 = 14;
pub const TCR_EL2_TG0_WITHOUT_E2H: u64 = 0b11 << TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H;
pub const TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H: u64 = 0;
pub const TCR_EL2_T0SZ_WITHOUT_E2H: u64 = 0b111111 << TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H;

/* CLIDR_EL1 */
pub const CLIDR_EL1_LOC_BITS_OFFSET: u64 = 24;
pub const CLIDR_EL1_LOC: u64 = 0b111 << CLIDR_EL1_LOC_BITS_OFFSET;

/* CCSIDR_EL1 */
pub const CCSIDR_EL1_NUM_SETS_BITS_OFFSET: u64 = 13;
pub const CCSIDR_EL1_NUM_SETS: u64 = 0x7FFF << CCSIDR_EL1_NUM_SETS_BITS_OFFSET;
pub const CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET: u64 = 3;
pub const CCSIDR_EL1_ASSOCIATIVITY: u64 = 0x3FF << CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET;
pub const CCSIDR_EL1_LINE_SIZE_BITS_OFFSET: u64 = 0;
pub const CCSIDR_EL1_LINE_SIZE: u64 = 0b111 << CCSIDR_EL1_LINE_SIZE_BITS_OFFSET;

#[inline(always)]
pub fn get_ttbr0_el2() -> u64 {
    let ttbr0_el2: u64;
    unsafe { asm!("mrs {:x}, ttbr0_el2", out(reg) ttbr0_el2) };
    ttbr0_el2
}

#[inline(always)]
pub fn set_ttbr0_el2(ttbr0_el2: u64) {
    unsafe { asm!("msr ttbr0_el2, {:x}", in(reg) ttbr0_el2) };
}

#[inline(always)]
pub fn get_tcr_el2() -> u64 {
    let tcr_el2: u64;
    unsafe { asm!("mrs {:x}, tcr_el2", out(reg) tcr_el2) };
    tcr_el2
}

#[inline(always)]
pub fn get_mair_el2() -> u64 {
    let mair_el2: u64;
    unsafe { asm!("mrs {:x}, mair_el2", out(reg) mair_el2) };
    mair_el2
}

#[inline(always)]
pub fn dsb() {
    unsafe { asm!("dsb sy") }
}

#[inline(always)]
pub fn isb() {
    unsafe { asm!("isb") }
}

/// Halt Loop
///
/// Stop the cpu.
/// This function does not support to stop all cpus.
pub fn halt_loop() -> ! {
    loop {
        unsafe { asm!("wfi") };
    }
}

#[inline(always)]
pub fn flush_tlb_el2() {
    unsafe {
        asm!(
            "
             dsb   ishst
             tlbi  alle2is
             dsb   sy
             isb"
        )
    };
}

pub fn clean_data_cache_all() {
    dsb();
    let clidr_el1: u64;
    unsafe { asm!("mrs {:x}, clidr_el1", out(reg) clidr_el1) };
    let loc = (clidr_el1 & CLIDR_EL1_LOC) >> CLIDR_EL1_LOC_BITS_OFFSET;
    for cache_level in 0..loc {
        let cache_type = (clidr_el1 >> (3 * cache_level)) & 0b111;
        let ccsidr_el1: u64;

        if cache_type <= 1 {
            /* Data Cache is not available */
            continue;
        }
        unsafe {
            asm!("
                    msr csselr_el1, {:x}
                    isb
                    mrs {:x}, ccsidr_el1
                ", in(reg) cache_level << 1, out(reg) ccsidr_el1)
        };

        let line_size =
            ((ccsidr_el1 & CCSIDR_EL1_LINE_SIZE) >> CCSIDR_EL1_LINE_SIZE_BITS_OFFSET) + 4;
        let associativity =
            ((ccsidr_el1 & CCSIDR_EL1_ASSOCIATIVITY) >> CCSIDR_EL1_ASSOCIATIVITY_BITS_OFFSET) + 1;
        let num_sets = ((ccsidr_el1 & CCSIDR_EL1_NUM_SETS) >> CCSIDR_EL1_NUM_SETS_BITS_OFFSET) + 1;
        let set_way_a = (associativity as u32 - 1).leading_zeros();

        for set in 0..num_sets {
            for way in 0..associativity {
                /* C5.3.13 DC CISW, Data or unified Cache line Clean and Invalidate by Set/Way (ARM DDI 0487G.a ID011921)
                 *
                 * SetWay[31:4]
                 * * Way, bits[31:32-A], the number of the way to operate on.
                 * * Set, bits[B-1:L], the number of the set to operate on.
                 * Bits[L-1:4] are RES0.
                 * A = Log2(ASSOCIATIVITY), L = Log2(LINELEN), B = (L + S), S = Log2(NSETS).
                 *
                 * Level, bits [3:1]
                 */
                let set_way = (way << set_way_a) | (set << line_size) | (cache_level << 1);
                unsafe { asm!("DC CISW, {:x}", in(reg) set_way) };
            }
        }
    }
    dsb();
    isb();
    unsafe { asm!("msr csselr_el1, {:x}", in(reg) 0) }; /* Restore CSSELR_EL1 */
}
