// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

#![no_std]
#![no_main]

mod uefi;
#[macro_use]
mod console;
mod cpu;
mod elf;
mod paging;

use cpu::*;
use paging::{PAGE_MASK, PAGE_SHIFT};
use uefi::{boot_service::EfiBootServices, file, EfiHandle, EfiStatus, EfiSystemTable};

use core::mem::MaybeUninit;

static mut ORIGINAL_PAGE_TABLE: usize = 0;

static mut BOOT_SERVICES: *const EfiBootServices = core::ptr::null();

#[macro_export]
macro_rules! bitmask {
    ($high:expr,$low:expr) => {
        ((1 << (($high - $low) + 1)) - 1) << $low
    };
}

#[no_mangle]
extern "C" fn efi_main(image_handle: EfiHandle, system_table: *mut EfiSystemTable) -> ! {
    unsafe { console::DEFAULT_CONSOLE.init((*system_table).console_output_protocol) };
    let b_s = unsafe { &*((*system_table).efi_boot_services) };
    unsafe { BOOT_SERVICES = b_s };

    let entry_point = load_hypervisor(image_handle, b_s);

    println!("Call the hypervisor(Entry Point: {:#X})", entry_point);

    dsb();
    isb();
    unsafe {
        (core::mem::transmute::<usize, extern "C" fn(EfiHandle, *mut EfiSystemTable, usize)>(
            entry_point,
        ))(image_handle, system_table, ORIGINAL_PAGE_TABLE)
    };

    unreachable!();
}

/// Load hypervisor_kernel to [`common::HYPERVISOR_VIRTUAL_BASE_ADDRESS`]
///
/// This function loads hypervisor_kernel according to ELF header.
/// The hypervisor_kernel will be loaded from [`common::HYPERVISOR_PATH`]
///
/// Before loads the hypervisor, this will save original TTBR0_EL2 into [`ORIGINAL_PAGE_TABLE`] and
/// create new TTBR0_EL2 by copying original page table tree.
///
/// # Panics
/// If the loading is failed(including memory allocation, calling UEFI functions), this function panics
///
/// # Result
/// Returns the entry point of hypervisor_kernel
fn load_hypervisor(image_handle: EfiHandle, b_s: &EfiBootServices) -> usize {
    const PATH: &str = "EFI\\BOOT\\hypervisor";

    let root_protocol =
        file::EfiFileProtocol::open_root_dir(image_handle, b_s).expect("Failed to open the volume");
    let mut file_name_utf16: [u16; PATH.len() + 1] = [0; PATH.len() + 1];

    for (i, e) in PATH.encode_utf16().enumerate() {
        file_name_utf16[i] = e;
    }
    let hypervisor_protocol = file::EfiFileProtocol::open_file(root_protocol, &file_name_utf16)
        .expect("Failed to open the hypervisor binary file");

    /* Read ElfHeader */
    let mut elf_header: MaybeUninit<elf::Elf64Header> = MaybeUninit::uninit();
    const ELF64_HEADER_SIZE: usize = core::mem::size_of::<elf::Elf64Header>();
    let read_size = hypervisor_protocol
        .read(elf_header.as_mut_ptr() as *mut u8, ELF64_HEADER_SIZE)
        .expect("Failed to read Elf header");
    if read_size != core::mem::size_of_val(&elf_header) {
        panic!(
            "Expected {} bytes, but read {} bytes",
            ELF64_HEADER_SIZE, read_size
        );
    }

    let elf_header = unsafe { elf_header.assume_init() };
    if !elf_header.check_elf_header() {
        panic!("Failed to load the hypervisor");
    }
    let program_header_entries_size =
        elf_header.get_program_header_entry_size() * elf_header.get_num_of_program_header_entries();
    let program_header_pool = b_s
        .alloc_pool(program_header_entries_size)
        .expect("Failed to allocate the pool for the program header");
    hypervisor_protocol
        .seek(elf_header.get_program_header_offset())
        .expect("Failed to seek for the program header");
    let read_size = hypervisor_protocol
        .read(program_header_pool as *mut u8, program_header_entries_size)
        .expect("Failed to read hypervisor");
    if read_size != program_header_entries_size {
        panic!(
            "Expected {} bytes, but read {} bytes",
            program_header_entries_size, read_size
        );
    }

    /* Switch PageTable */
    let cloned_page_table = paging::clone_page_table();
    unsafe { ORIGINAL_PAGE_TABLE = get_ttbr0_el2() as usize };
    set_ttbr0_el2(cloned_page_table as u64);
    println!(
        "Switched TTBR0_EL2 from {:#X} to {:#X}",
        unsafe { ORIGINAL_PAGE_TABLE },
        cloned_page_table
    );

    for index in 0..elf_header.get_num_of_program_header_entries() {
        if let Some(info) = elf_header.get_segment_info(index, program_header_pool) {
            println!("{:#X?}", info);
            if info.memory_size == 0 {
                continue;
            }
            let pages = (((info.memory_size - 1) & PAGE_MASK) >> PAGE_SHIFT) + 1;
            let physical_base_address =
                allocate_memory(pages).expect("Failed to allocate memory for hypervisor");

            if info.file_size > 0 {
                hypervisor_protocol
                    .seek(info.file_offset)
                    .expect("Failed to seek for hypervisor segments");
                let read_size = hypervisor_protocol
                    .read(physical_base_address as *mut u8, info.file_size)
                    .expect("Failed to read hypervisor segments");
                if read_size != info.file_size {
                    panic!(
                        "Expected {} bytes, but read {} bytes",
                        info.file_size, read_size
                    );
                }
            }

            if info.memory_size - info.file_size > 0 {
                unsafe {
                    core::ptr::write_bytes(
                        (physical_base_address + info.file_size) as *mut u8,
                        0,
                        info.memory_size - info.file_size,
                    )
                };
            }
            dsb();
            paging::map_address(
                physical_base_address,
                info.virtual_base_address,
                pages << PAGE_SHIFT,
                info.readable,
                info.writable,
                info.executable,
                false,
            )
            .expect("Failed to map hypervisor");
        }
    }

    let entry_point = elf_header.get_entry_point();
    if let Err(e) = b_s.free_pool(program_header_pool) {
        println!("Failed to free the pool: {:?}", e);
    }
    if let Err(e) = hypervisor_protocol.close_file() {
        println!("Failed to clone the HypervisorProtocol: {:?}", e);
    }
    if let Err(e) = root_protocol.close_file() {
        println!("Failed to clone the RootProtocol: {:?}", e);
    }

    entry_point
}

fn allocate_memory(pages: usize) -> Result<usize, EfiStatus> {
    unsafe { &*BOOT_SERVICES }.alloc_highest_memory(pages, usize::MAX)
}

#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("\n\nBoot Loader Panic: {}", info);
    cpu::halt_loop()
}
