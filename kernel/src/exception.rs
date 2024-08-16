//Copyright 2023 Manami Mori
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

//例外テーブルつくるよ

use crate::cpu::*;
use crate::get_esr_el2;
use crate::mmio::pl011;
use crate::PL011;
use crate::RANGE;
use core::arch::global_asm;
use core::u64;

pub const ESR_EL2_EC_BITS_OFFSET: u64 = 26;
pub const ESR_EL2_EC: u64 = 0b111111 << ESR_EL2_EC_BITS_OFFSET;
pub const ESR_EL2_EC_DATA_ABORT: u64 = 0b100100 << 26;
pub const ESR_EL2_ISS_ISV: u64 = 1 << 24;
pub const ESR_EL2_ISS_SAS_BITS_OFFSET: u64 = 22;
pub const ESR_EL2_ISS_SAS: u64 = 0b11 << ESR_EL2_ISS_SAS_BITS_OFFSET;
pub const ESR_EL2_ISS_SRT_BITS_OFFSET: u64 = 16;
pub const ESR_EL2_ISS_SRT: u64 = 0b11111 << ESR_EL2_ISS_SRT_BITS_OFFSET;
pub const ESR_EL2_ISS_SF: u64 = 1 << 15;
pub const ESR_EL2_ISS_WNR: u64 = 1 << 6;

pub const HPFAR_EL2_FIPA_BITS_OFFSET: u64 = 4;
pub const HPFAR_EL2_FIPA: u64 = ((1 << 44) - 1) & !((1 << 4) - 1);

const EC_SMC_AA64: u64 = 0b010111;
const EC_DATA_ABORT:u64 = 0b100100;
const UART_DR: usize = 0x000;
const UART_FR: usize = 0x018;

#[repr(C)]
pub struct Registers {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    padding: u64,
}

global_asm!(
    "
.section .text
.balign 0x800
//.size   exception_table, 0x800
.global exception_table
exception_table:

.balign 0x080
synchronous_current_el_stack_pointer_0:
    b   synchronous_current_el_stack_pointer_0

.balign 0x080
irq_current_el_stack_pointer_0:
    b   irq_current_el_stack_pointer_0

.balign 0x080
fiq_current_el_stack_pointer_0:
    b   fiq_current_el_stack_pointer_0

.balign 0x080
s_error_current_el_stack_pointer_0:
    b   s_error_current_el_stack_pointer_0

.balign 0x080
synchronous_current_el_stack_pointer_x:
    b   synchronous_current_el_stack_pointer_x

.balign 0x080
irq_current_el_stack_pointer_x:
    sub sp,   sp, #(8 * 32)
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mov  x0, sp
    adr x30, exit_exception
    b   irq_handler

.balign 0x080
fiq_current_el_stack_pointer_x:
    b   fiq_current_el_stack_pointer_x

.balign 0x080
s_error_current_el_stack_pointer_x:
    b   s_error_current_el_stack_pointer_x

.balign 0x080
synchronous_lower_el_aarch64:
    sub sp,   sp, #(8 * 32)
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mov  x0, sp
    adr x30, exit_exception
    b   synchronous_handler

.balign 0x080
irq_lower_el_aarch64:
    sub sp,   sp, #(8 * 32)
    stp x30, xzr, [sp, #( 15 * 16)]
    stp x28, x29, [sp, #( 14 * 16)]
    stp x26, x27, [sp, #( 13 * 16)]
    stp x24, x25, [sp, #( 12 * 16)]
    stp x22, x23, [sp, #( 11 * 16)]
    stp x20, x21, [sp, #( 10 * 16)]
    stp x18, x19, [sp, #(  9 * 16)]
    stp x16, x17, [sp, #(  8 * 16)]
    stp x14, x15, [sp, #(  7 * 16)]
    stp x12, x13, [sp, #(  6 * 16)]
    stp x10, x11, [sp, #(  5 * 16)]
    stp  x8,  x9, [sp, #(  4 * 16)]
    stp  x6,  x7, [sp, #(  3 * 16)]
    stp  x4,  x5, [sp, #(  2 * 16)]
    stp  x2,  x3, [sp, #(  1 * 16)]
    stp  x0,  x1, [sp, #(  0 * 16)]
    mov  x0, sp
    adr x30, exit_exception
    b   irq_handler

.balign 0x080
fiq_lower_el_aarch64:
    b   fiq_lower_el_aarch64

.balign 0x080
s_error_lower_el_aarch64:
    b   s_error_lower_el_aarch64

.balign 0x080
synchronous_lower_el_aarch32:
    b   synchronous_lower_el_aarch32

.balign 0x080
irq_lower_el_aarch32:
    b   irq_lower_el_aarch32

.balign 0x080
fiq_lower_el_aarch32:
    b   fiq_lower_el_aarch32

.balign 0x080
s_error_lower_el_aarch32:
    b   s_error_lower_el_aarch32

exit_exception:
    ldp x30, xzr, [sp, #( 15 * 16)]
    ldp x28, x29, [sp, #( 14 * 16)]
    ldp x26, x27, [sp, #( 13 * 16)]
    ldp x24, x25, [sp, #( 12 * 16)]
    ldp x22, x23, [sp, #( 11 * 16)]
    ldp x20, x21, [sp, #( 10 * 16)]
    ldp x18, x19, [sp, #(  9 * 16)]
    ldp x16, x17, [sp, #(  8 * 16)]
    ldp x14, x15, [sp, #(  7 * 16)]
    ldp x12, x13, [sp, #(  6 * 16)]
    ldp x10, x11, [sp, #(  5 * 16)]
    ldp  x8,  x9, [sp, #(  4 * 16)]
    ldp  x6,  x7, [sp, #(  3 * 16)]
    ldp  x4,  x5, [sp, #(  2 * 16)]
    ldp  x2,  x3, [sp, #(  1 * 16)]
    ldp  x0,  x1, [sp, #(  0 * 16)]
    add  sp,  sp, #(8 * 32)
    eret
"
);

#[no_mangle]
extern "C" fn irq_handler() {}

#[no_mangle]
extern "C" fn synchronous_handler(registers: *mut Registers) {
    /*println!("Synchronous Exception!");
    println!("Fault at {:#X}", get_elr_el2());*/
    let esr_el2 = get_esr_el2();
    let ec = (esr_el2 & ESR_EL2_EC) >> ESR_EL2_EC_BITS_OFFSET;
    match ec {
        EC_DATA_ABORT => data_abort_handler(unsafe { &mut *registers }, esr_el2),

        EC_SMC_AA64 => {
            /* Adjust return address */
            advance_elr_el2();
            let regs = unsafe { &mut *registers };
            let smc_number = 0; // esr_el2 & bitmask!(15, 0);
            pr_debug!("SecureMonitor Call: {:#X}", smc_number);
            pr_debug!("Registers: {:#X?}", regs);
            if regs.x0 == 0xC400_0003 {
                regs.x0 = (u64::MAX - 2);
                println!("Prevent smp");
            } else if smc_number == 0 {
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
            } else {
                print!("SMC {:#X} is not implemented.", smc_number);
                panic!();
                //handler_panic!(regs, "SMC {:#X} is not implemented.", smc_number);
            }
        }
        _ => {
            panic!("Unkown Exception: {}", ec >> ESR_EL2_EC_BITS_OFFSET);
        }
    }
}

fn data_abort_handler(registers: &mut Registers, esr_el2: u64) {
    if esr_el2 & ESR_EL2_ISS_ISV == 0 {
        panic!("Data Abort Info is not available.");
    }
    let is_64bit_register = (esr_el2 & ESR_EL2_ISS_SF) != 0;
    let access_width = match (esr_el2 & ESR_EL2_ISS_SAS) >> ESR_EL2_ISS_SAS_BITS_OFFSET {
        0b00 => 8,
        0b01 => 16,
        0b10 => 32,
        0b11 => 64,
        _ => unreachable!(),
    };
    let is_write_access = (esr_el2 & ESR_EL2_ISS_WNR) != 0;
    //println!("{:#X}",esr_el2);
    let register_number = ((esr_el2 & ESR_EL2_ISS_SRT) >> ESR_EL2_ISS_SRT_BITS_OFFSET) as usize;
    let register: &mut u64 =
        &mut unsafe { &mut *(registers as *mut _ as usize as *mut [u64; 32]) }[register_number];

    let address = (((get_hpfar_el2() & HPFAR_EL2_FIPA) >> HPFAR_EL2_FIPA_BITS_OFFSET)
        << crate::paging::PAGE_SHIFT)
        | (get_far_el2() & ((1 << crate::paging::PAGE_SHIFT) - 1));

    if (PL011 as u64..(PL011 + RANGE) as u64).contains(&address) {
        /* PL011 */
        let offset = (address - PL011 as u64) as usize;
        if is_write_access {
            let register_value = if is_64bit_register {
                *register
            } else {
                *register & (u32::MAX as u64)
            };
            pl011::mmio_write(offset, /*access_width,*/ register_value)
                .expect("Failed to handle MMIO");
        } else {
            *register = pl011::mmio_read(offset, access_width).expect("Failed to handle MMIO");
        }
    } else {
        println!(
            "{:#X} {} {}{}({} Bits)(Value: {:#X})",
            address,
            if is_write_access { "<=" } else { "=>" },
            if is_64bit_register { "X" } else { "W" },
            register_number,
            access_width,
            *register
        );
    }

    advance_elr_el2();
}

pub fn setup_exception() {
    extern "C" {
        static exception_table: *const u8;
    }
    unsafe { set_vbar_el2(&exception_table as *const _ as usize as u64) }
}
