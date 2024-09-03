// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Paging
//!

use crate::cpu::{
    clean_data_cache_all, flush_tlb_el2, get_mair_el2, get_tcr_el2, get_ttbr0_el2,
    TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H, TCR_EL2_DS_WITHOUT_E2H,
    TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_T0SZ_WITHOUT_E2H,
    TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H, TCR_EL2_TG0_WITHOUT_E2H,
};
use crate::{allocate_memory, bitmask};

pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);

pub const PAGE_TABLE_SIZE: usize = 0x1000;

pub const PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET: u64 = 50;
pub const PAGE_DESCRIPTORS_CONTIGUOUS: u64 = 1 << 52;
pub const PAGE_DESCRIPTORS_NX_BIT_OFFSET: u64 = 54;

pub const PAGE_DESCRIPTORS_NT: u64 = 1 << 16;
pub const PAGE_DESCRIPTORS_AF_BIT_OFFSET: u64 = 10;
pub const PAGE_DESCRIPTORS_AF: u64 = 1 << PAGE_DESCRIPTORS_AF_BIT_OFFSET;
pub const PAGE_DESCRIPTORS_SH_BITS_OFFSET: u64 = 8;
pub const PAGE_DESCRIPTORS_SH_INNER_SHAREABLE: u64 = 0b11 << PAGE_DESCRIPTORS_SH_BITS_OFFSET;
pub const PAGE_DESCRIPTORS_AP_BITS_OFFSET: u64 = 6;

pub const MEMORY_PERMISSION_READABLE_BIT: u8 = 0;
pub const MEMORY_PERMISSION_WRITABLE_BIT: u8 = 1;
pub const MEMORY_PERMISSION_EXECUTABLE_BIT: u8 = 2;

#[derive(Copy, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Shareability {
    NonShareable,
    OuterShareable,
    InterShareable,
}

pub const fn extract_output_address(descriptor: u64, page_shift: usize) -> usize {
    (descriptor
        & bitmask!(
            PAGE_DESCRIPTORS_UPPER_ATTRIBUTES_OFFSET - 1,
            page_shift as u64
        )) as usize
}

pub const fn is_descriptor_table_or_level_3_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b11
}

pub const fn is_block_descriptor(descriptor: u64) -> bool {
    descriptor & 0b11 == 0b01
}

pub const fn create_attributes_for_stage_1(
    permission: u8,
    memory_attribute: u8,
    is_block_entry: bool,
) -> u64 {
    let nx_bit: u64 = if (permission & (1 << MEMORY_PERMISSION_EXECUTABLE_BIT)) != 0 {
        0
    } else {
        1
    } << PAGE_DESCRIPTORS_NX_BIT_OFFSET;
    let access_permission: u64 = if (permission & (1 << MEMORY_PERMISSION_WRITABLE_BIT)) != 0 {
        0b00
    } else {
        0b10
    } << PAGE_DESCRIPTORS_AP_BITS_OFFSET;

    nx_bit
        | PAGE_DESCRIPTORS_AF
        | PAGE_DESCRIPTORS_SH_INNER_SHAREABLE
        | nx_bit
        | access_permission
        | (memory_attribute << 2) as u64
        | if is_block_entry { 0b01 } else { 0b11 }
}

pub const fn table_level_to_table_shift(
    translation_granule_shift: usize,
    table_level: i8,
) -> usize {
    translation_granule_shift + 9 * (3 - table_level) as usize
}

/// Get first level of page table of TTBR_EL2
///
/// # Arguments
/// * `tcr_el2` - the value to calculate first level
///
/// # Result
/// Returns (first level of page table, the left-shift value of first level table's granule)
pub const fn get_initial_page_table_level_and_bits_to_shift(tcr_el2: u64) -> (i8, usize) {
    let tcr_el2_ds =
        ((tcr_el2 & TCR_EL2_DS_WITHOUT_E2H) >> TCR_EL2_DS_BIT_OFFSET_WITHOUT_E2H) as u8;
    let tcr_el2_tg0 = (tcr_el2 & TCR_EL2_TG0_WITHOUT_E2H) >> TCR_EL2_TG0_BITS_OFFSET_WITHOUT_E2H;
    let tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as usize;
    let page_shift = 12 + (tcr_el2_tg0 << 1) as usize;

    /* aarch64/translation/walk/AArch64.TranslationTableWalk (J1-7982) */
    let first_level = 4
        - (1 + ((64 - tcr_el2_t0sz /* TTBR1_EL2ではここが t1sz(TCR_EL2[21:16] */ - page_shift - 1)
            / (page_shift - 3))) as i8;

    if tcr_el2_ds == 0 && first_level == -1 {
        panic!("5-Level Paging with DS == 0 is invalid.");
    }
    (
        first_level,
        table_level_to_table_shift(page_shift, first_level),
    )
}

pub fn get_suitable_memory_attribute_index_from_mair_el2(is_device: bool) -> u8 {
    let mut mair_el2 = get_mair_el2();
    let suitable_attribute: u64 = if is_device { 0x00 } else { 0xff };
    for index in 0..7 {
        let attribute = mair_el2 & 0xff;
        if attribute == suitable_attribute {
            return index;
        }
        mair_el2 >>= 8;
    }
    panic!("Attr=={:#X} is not found...", suitable_attribute);
}

fn _clone_page_table(table_address: usize, current_level: i8) -> usize {
    let cloned_table_address = allocate_memory(1).expect("Failed to allocate page table");

    let cloned_table = unsafe {
        &mut *(cloned_table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };
    unsafe {
        *cloned_table =
            *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };
    if current_level == 3 {
        return cloned_table_address;
    }
    for e in cloned_table {
        if is_descriptor_table_or_level_3_descriptor(*e) {
            let next_level_table_address = extract_output_address(*e, PAGE_SHIFT);
            *e = ((*e) & !(next_level_table_address as u64))
                | (_clone_page_table(next_level_table_address, current_level + 1) as u64);
        }
    }

    clean_data_cache_all();
    flush_tlb_el2();
    cloned_table_address
}

/// Clone TTBR0_EL2
///
/// Clone the page table tree of TTBR0_EL2。
///
/// # Panics
/// If memory allocation is failed, this function panics
///
/// # Result
/// Returns Cloned Page Table Address
pub fn clone_page_table() -> usize {
    let page_table_address = get_ttbr0_el2() as usize;
    let tcr_el2 = get_tcr_el2();
    let first_table_level = get_initial_page_table_level_and_bits_to_shift(tcr_el2).0;
    _clone_page_table(page_table_address, first_table_level)
}

/// Map physical address recursively
///
/// This will map memory area upto `num_of_remaining_pages`.
/// This will call itself recursively, and map address until `num_of_remaining_pages` == 0 or reached the end of table.
/// When all page is mapped successfully, `num_of_remaining_pages` has been 0.
///
/// # Arguments
/// * `physical_address` - The address to map
/// * `virtual_address` - The address to associate with `physical_address`
/// * `num_of_remaining_pages` - The number of page entries to be mapped, this value will be changed
/// * `table_address` - The table address to set up in this function
/// * `table_level` -  The tree level of `table_address`, the max value is 3
/// * `permission` - The attribute for memory, Bit0: is_readable, Bit1: is_writable, Bit2: is_executable
/// * `memory_attribute` - The index of MAIR_EL2 to apply the mapping area
/// * `t0sz` - The value of TCR_EL2::T0SZ
fn map_address_recursive(
    physical_address: &mut usize,
    virtual_address: &mut usize,
    num_of_remaining_pages: &mut usize,
    table_address: usize,
    table_level: i8,
    permission: u8,
    memory_attribute: u8,
    t0sz: u8,
) -> Result<(), ()> {
    let shift_level = table_level_to_table_shift(PAGE_SHIFT, table_level);
    let mut table_index = (*virtual_address >> shift_level) & 0x1FF;

    if table_level == 3 {
        let current_table = unsafe {
            &mut *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
        };
        let num_of_pages = if *num_of_remaining_pages + table_index > 512 {
            512 - table_index
        } else {
            *num_of_remaining_pages
        };
        let attributes = create_attributes_for_stage_1(permission, memory_attribute, false);

        for index in table_index..(table_index + num_of_pages) {
            current_table[index] = *physical_address as u64 | attributes;
            *physical_address += PAGE_SIZE;
            *virtual_address += PAGE_SIZE;
        }
        *num_of_remaining_pages -= num_of_pages;
        clean_data_cache_all();
        return Ok(());
    }
    let current_table = unsafe {
        &mut *(table_address as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
    };

    while *num_of_remaining_pages != 0 {
        if table_index >= 512 {
            break;
        }
        let target_descriptor = &mut current_table[table_index];

        if table_level > 1
            && (*physical_address & ((1usize << shift_level) - 1)) == 0
            && (*virtual_address & ((1usize << shift_level) - 1)) == 0
            && *num_of_remaining_pages >= 512usize.pow((3 - table_level) as u32)
        {
            pr_debug!(
                "Creating BlockEntry: VA: {:#X}, PA: {:#X}, TableLevel: {}",
                *virtual_address,
                *physical_address,
                table_level
            );

            *target_descriptor = *physical_address as u64
                | create_attributes_for_stage_1(permission, memory_attribute, true);

            *physical_address += 1 << shift_level;
            *virtual_address += 1 << shift_level;
            *num_of_remaining_pages -= 512usize.pow((3 - table_level) as u32);
        } else {
            let mut created_entry: Option<u64> = None;

            if !is_descriptor_table_or_level_3_descriptor(*target_descriptor) {
                let allocated_table_address =
                    allocate_page_table_for_stage_1(table_level, t0sz, false)?;

                if is_block_descriptor(*target_descriptor) {
                    pr_debug!(
                        "Convert the block descriptor({:#b}) to table descriptor",
                        *target_descriptor
                    );

                    let mut block_physical_address =
                        extract_output_address(*target_descriptor, PAGE_SHIFT);
                    let mut descriptor_attribute =
                        *target_descriptor ^ (block_physical_address as u64);
                    let next_level_page = unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    };

                    if table_level + 1 == 3 {
                        descriptor_attribute |= 0b11;
                        descriptor_attribute &= !PAGE_DESCRIPTORS_NT;
                    }
                    descriptor_attribute &= !PAGE_DESCRIPTORS_CONTIGUOUS; /* Currently, needless */

                    for e in next_level_page {
                        *e = (block_physical_address as u64) | descriptor_attribute;
                        block_physical_address += 1 << (shift_level - 9);
                    }
                    clean_data_cache_all();
                } else {
                    /* set_mem */
                    for e in unsafe {
                        &mut *(allocated_table_address
                            as *mut [u64; PAGE_TABLE_SIZE / core::mem::size_of::<u64>()])
                    } {
                        *e = 0;
                    }
                    clean_data_cache_all();
                }

                /* TODO: 52bit OA support */
                created_entry = Some(allocated_table_address as u64 | 0b11);
                pr_debug!("Allocated: {:#X}", allocated_table_address);
            }
            map_address_recursive(
                physical_address,
                virtual_address,
                num_of_remaining_pages,
                extract_output_address(created_entry.unwrap_or(*target_descriptor), PAGE_SHIFT),
                table_level + 1,
                permission,
                memory_attribute,
                t0sz,
            )?;

            if let Some(new_descriptor) = created_entry {
                *target_descriptor = new_descriptor;
            }
        }
        table_index += 1;
    }
    Ok(())
}

/// Map address
///
/// This will map virtual address into physical address
/// The virtual address is for EL2.
///
/// # Arguments
/// * `physical_address` - The address to map
/// * `virtual_address` - The address to associate with `physical_address`
/// * `size` - The map size
/// * `readable` - If true, the memory area will be readable
/// * `writable` - If true, the memory area will be writable
/// * `executable` - If true, the memory area will be executable
/// * `is_device` - If true, the cache control of the memory area will become for device memory
///
/// # Result
/// If mapping is succeeded, returns Ok(()), otherwise returns Err(())
pub fn map_address(
    mut physical_address: usize,
    mut virtual_address: usize,
    size: usize,
    readable: bool,
    writable: bool,
    executable: bool,
    is_device: bool,
) -> Result<(), ()> {
    if (physical_address & !PAGE_MASK) != 0 {
        println!("Physical Address is not aligned.");
        return Err(());
    }
    let aligned_size = if (size & !PAGE_MASK) != 0 {
        (size & !PAGE_MASK) + PAGE_SIZE
    } else {
        size
    };
    let mut num_of_needed_pages = aligned_size >> PAGE_SHIFT;
    let tcr_el2 = get_tcr_el2();

    let tcr_el2_t0sz =
        ((tcr_el2 & TCR_EL2_T0SZ_WITHOUT_E2H) >> TCR_EL2_T0SZ_BITS_OFFSET_WITHOUT_E2H) as u32;

    let (table_level, _) = get_initial_page_table_level_and_bits_to_shift(tcr_el2);
    let min_t0sz = (virtual_address + size).leading_zeros();
    assert!(min_t0sz >= tcr_el2_t0sz);

    map_address_recursive(
        &mut physical_address,
        &mut virtual_address,
        &mut num_of_needed_pages,
        get_ttbr0_el2() as usize,
        table_level,
        (readable as u8) << MEMORY_PERMISSION_READABLE_BIT
            | (writable as u8) << MEMORY_PERMISSION_WRITABLE_BIT
            | (executable as u8) << MEMORY_PERMISSION_EXECUTABLE_BIT,
        get_suitable_memory_attribute_index_from_mair_el2(is_device),
        tcr_el2_t0sz as u8,
    )?;

    if num_of_needed_pages != 0 {
        println!(
            "Failed to map address(remaining_pages:{} != 0",
            num_of_needed_pages
        );
        return Err(());
    }
    flush_tlb_el2();
    pr_debug!(
        "Mapped {:#X} Bytes({} Pages)",
        aligned_size,
        aligned_size >> PAGE_SHIFT
    );
    Ok(())
}

/// Allocate page table for stage 1 with suitable address alignment
#[inline(always)]
fn allocate_page_table_for_stage_1(
    look_up_level: i8,
    t0sz: u8,
    is_for_ttbr: bool,
) -> Result<usize, ()> {
    let alignment = if is_for_ttbr {
        ((64 - ((PAGE_SHIFT - 3) * (4 - look_up_level) as usize) - t0sz as usize).max(4)).min(12)
    } else {
        PAGE_SHIFT
    };
    assert_eq!(alignment, 12);
    match allocate_memory(1) {
        Ok(address) => Ok(address),
        Err(err) => {
            println!("Failed to allocate the page table: {:?}", err);
            Err(())
        }
    }
}
