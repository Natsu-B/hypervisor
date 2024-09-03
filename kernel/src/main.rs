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

// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]

use core::arch::asm;
use core::num::NonZeroUsize;
use core::usize;

use exception::setup_exception;
use print::set_color;
use uefi::serial_port::SerialPortInfo;
use uefi::EfiConfigurationTable;
use system_info::SystemInformation;

use crate::cpu::*;
use crate::paging::PAGE_SHIFT;
use crate::paging::PAGE_SIZE;
use crate::uefi::{EfiHandle, EfiSystemTable, EFI_ACPI_20_TABLE_GUID, EFI_DTB_TABLE_GUID};

const PL011: usize = 0x900_0000; //for qm
//const PL011: usize = 0x107D001000;//for raspi 5
const RANGE: usize = 0x1000;

const UART_DR: usize = 0x000;
const UART_FR: usize = 0x018;

#[macro_use]
mod console;
mod cpu;
mod exception;
mod paging;
mod print;
mod uefi;
mod mmio {
    pub mod pl011;
}
mod system_info;

static mut IMAGE_HANDLE: EfiHandle = 0;
static mut SYSTEM_TABLE: *const EfiSystemTable = core::ptr::null();
/// The memory size to allocate
pub const ALLOC_SIZE: usize = 256 * 1024 * 1024; /* 256 MB */
pub const MAX_PHYSICAL_ADDRESS: usize = (1 << (48 + 1)) - 1;
pub const STACK_PAGES: usize = 16;

#[macro_export]
macro_rules! bitmask {
    ($high:expr,$low:expr) => {
        ((1 << (($high - $low) + 1)) - 1) << $low
    };
}

#[no_mangle]
extern "C" fn main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
    original_page_table: usize,
    system_info: SystemInformation,
) -> ! {
    let system_table = unsafe { &*system_table };
    unsafe {
        IMAGE_HANDLE = image_handle;
        SYSTEM_TABLE = system_table;
        console::DEFAULT_CONSOLE.init((*system_table).console_output_protocol);
    }

    if let Some(serial_port) = system_info.serial_port
    {
        paging::setup_stage_2_translation(serial_port, RANGE)
            .expect("Failed to setup Stage2 Paging");
    } else {
        println!("Error: Cannot detect serial port");
        paging::setup_stage_2_translation(PL011, RANGE);
    }

    /* Stack for BSP */
    let stack_address = allocate_memory(STACK_PAGES, None).expect("Failed to alloc stack")
        + (STACK_PAGES << PAGE_SHIFT);

    println!("Setup EL1");
    /* Disable IRQ/FIQ */
    /* After disabling IRQ/FIQ, we should avoid calling UEFI functions */
    local_irq_fiq_save();

    set_up_el1();
    setup_exception();
    /* Jump to EL1(el1_main) */
    el2_to_el1(el1_main as *const fn() as usize, stack_address);
    panic!("Failed to jump EL1");
}

/// Allocate memory
///
/// # Arguments
/// * `pages` - The number of pages to allocate, the allocation size is `pages` << [`PAGE_SHIFT`]
/// * `align` - The alignment of the returned address, if `None`, [`PAGE_SHIFT`] will be used
///
/// # Result
/// If the allocation is succeeded, Ok(start_address), otherwise Err(())
pub fn allocate_memory(pages: usize, align: Option<usize>) -> Result<usize, ()> {
    let margin = if let Some(align) = align {
        align - PAGE_SHIFT
    } else {
        0
    };
    loop {
        let mut address = unsafe { &*((*SYSTEM_TABLE).efi_boot_services) }
            .alloc_highest_memory(pages + margin, MAX_PHYSICAL_ADDRESS)
            .expect("Failed to init memory pool");
        if let Some(align) = align {
            for _ in 0..=margin {
                if address & ((1 << align) - 1) != 0 {
                    address += PAGE_SIZE;
                } else {
                    return Ok(address);
                }
            }
            println!("Retry...");
        } else {
            return Ok(address);
        }
    }
} /*
  pub fn allocate_memory(pages: usize, align: Option<usize>) -> Result<usize, ()> {
      let align = align.unwrap_or(PAGE_SHIFT);
      loop {
          let address = unsafe { &*((*SYSTEM_TABLE).efi_boot_services) }
              .alloc_highest_memory(pages, MAX_PHYSICAL_ADDRESS)
              .expect("Failed to init memory pool");
          if (address & ((1 << align) - 1)) != 0 {
              continue;
          }
          return Ok(address);
      }
  }*/

fn set_up_el1() {
    /* CNTHCTL_EL2 & CNTVOFF_EL2 */
    set_cnthctl_el2(CNTHCTL_EL2_EL1PCEN | CNTHCTL_EL2_EL1PCTEN);
    set_cntvoff_el2(0);

    /* HSTR_EL2 */
    unsafe { asm!("msr hstr_el2, xzr") };

    /* VPIDR_EL2 & VMPIDR_EL2 */
    unsafe {
        asm!("  mrs {t}, midr_el1
                msr vpidr_el2, {t}
                mrs {t}, mpidr_el1
                msr vmpidr_el2, {t}", t = out(reg) _)
    };

    /* CPACR_EL1 & CPTR_EL2 */
    let cptr_el2_current = get_cptr_el2();
    let mut cpacr_el1: u64 = 0;
    cpacr_el1 |= ((((cptr_el2_current) & CPTR_EL2_ZEN) >> CPTR_EL2_ZEN_BITS_OFFSET)
        << CPACR_EL1_ZEN_BITS_OFFSET)
        | ((((cptr_el2_current) & CPTR_EL2_FPEN) >> CPTR_EL2_FPEN_BITS_OFFSET)
            << CPACR_EL1_FPEN_BITS_OFFSET);
    cpacr_el1 |= 0b11 << CPACR_EL1_FPEN_BITS_OFFSET; /* TODO: inspect why we must set 0b11 */
    cpacr_el1 |= ((cptr_el2_current & CPTR_EL2_TTA_WITHOUT_E2H)
        >> CPTR_EL2_TTA_BIT_OFFSET_WITHOUT_E2H)
        << CPACR_EL1_TTA_BIT_OFFSET;

    let mut cptr_el2: u64 = cptr_el2_current | CPTR_EL2_ZEN_NO_TRAP | CPTR_EL2_FPEN_NO_TRAP /*| CPTR_EL2_RES1*/;
    cptr_el2 &= !((1 << 28) | (1 << 30) | (1 << 31));
    set_cpacr_el1(cpacr_el1);
    isb();
    /* CPTR_EL2 will be set after HCR_EL2 */

    /* MAIR_EL1(Copy MAIR_EL2) */
    set_mair_el1(get_mair_el2());

    /* TTBR0_EL1 */
    set_ttbr0_el1(get_ttbr0_el2());

    /* TCR_EL1 */

    let mut tcr_el1: u64 = 0;
    let tcr_el2 = get_tcr_el2();
    /* Copy same bitfields */
    tcr_el1 |= tcr_el2 & ((1 << 16) - 1);

    tcr_el1 |= ((tcr_el2 & TCR_EL2_DS_WITHOUT_E2H) >> TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_DS_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_TCMA_WITHOUT_E2H) >> TCR_EL2_TCMA_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_TCMA0_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_TBID_WITHOUT_E2H) >> TCR_EL2_TBID_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_TBID0_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_HWU_WITHOUT_E2H) >> TCR_EL2_HWU_BITS_OFFSET_WITHOUT_E2H)
        << TCR_EL1_HWU_BITS_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_HPD_WITHOUT_E2H) >> TCR_EL2_HPD_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_HPD0_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_HD_WITHOUT_E2H) >> TCR_EL2_HD_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_HD_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_HA_WITHOUT_E2H) >> TCR_EL2_HA_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_HA_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_TBI_WITHOUT_E2H) >> TCR_EL2_TBI_BIT_OFFSET_WITHOUT_E2H)
        << TCR_EL1_TBI0_BIT_OFFSET;
    tcr_el1 |= ((tcr_el2 & TCR_EL2_PS_WITHOUT_E2H) >> TCR_EL2_PS_BITS_OFFSET_WITHOUT_E2H)
        << TCR_EL1_IPS_BITS_OFFSET;
    tcr_el1 |= TCR_EL1_EPD1; /* Disable TTBR1_EL1 */

    set_tcr_el1(tcr_el1);

    /* SCTLR_EL1(Copy SCTLR_EL2) */
    set_sctlr_el1(get_sctlr_el2());

    /* VBAR_EL1 */
    set_vbar_el1(get_vbar_el2());

    /* HCR_EL2 */
    let hcr_el2 = HCR_EL2_FIEN | HCR_EL2_API | HCR_EL2_APK | HCR_EL2_RW | HCR_EL2_TSC | HCR_EL2_VM;
    set_hcr_el2(hcr_el2);
    isb();
    set_cptr_el2(cptr_el2);
}

extern "C" fn el1_main() -> ! {
    use crate::print::put_free;
    set_color(2);
    put_free("Hello,");
    set_color(4);
    put_free("world!\n");
    set_color(3);
    put_free("Let's");
    set_color(5);
    put_free(" make");
    set_color(7);
    put_free(" a");
    set_color(6);
    put_free(" hypervisor!!\n");
    set_color(0);

    //halt_loop();
    exit_bootloader();
}

fn exit_bootloader() -> ! {
    unsafe {
        ((*(*SYSTEM_TABLE).efi_boot_services).exit)(
            IMAGE_HANDLE,
            uefi::EfiStatus::EfiSuccess,
            0,
            core::ptr::null(),
        );
    }
    panic!("Failed to exit");
}

fn el2_to_el1(el1_entry_point: usize, el1_stack_pointer: usize) {
    unsafe {
        asm!("
            msr elr_el2, {entry_point}
            mov {tmp}, sp
            msr sp_el1, {tmp}
            mov sp, {stack_pointer}
            mov {tmp}, (1 << 7) |(1 << 6) | (1 << 2) | (1) // EL1h(EL1 + Use SP_EL1)
            msr spsr_el2, {tmp}
            isb
            eret",
        tmp = in(reg) 0u64,
        entry_point = in(reg) el1_entry_point,
        stack_pointer = in(reg) el1_stack_pointer,
        options(noreturn)
        )
    }
}

#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\n\nBoot Loader Panic: {}", info);
    halt_loop()
}
