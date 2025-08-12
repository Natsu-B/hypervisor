#![cfg_attr(not(test), no_std)]

extern crate alloc;
use core::{
    alloc::{GlobalAlloc, Layout},
    cmp::max,
    mem::size_of,
    ptr::{NonNull, null_mut},
};
use mutex::SpinLock;

// usize = u64
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<usize>() == 8);

// linked list header
#[repr(C)]
struct LinkedList {
    magic_number: u32,
    is_allocated: bool,
    prev_header: Option<NonNull<LinkedList>>,
    next_header: Option<NonNull<LinkedList>>,
    size: usize,
}

const HEADER_SIZE: usize = size_of::<LinkedList>();
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(HEADER_SIZE == 32);
const HEADER_MAGIC: u32 = 0xA110CADE;

#[repr(C)]
struct BackPointer {
    magic_number: u64,
    list_header: NonNull<LinkedList>,
}

const BACK_POINTER_SIZE: usize = size_of::<BackPointer>();
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(BACK_POINTER_SIZE == 16);
const BACK_POINTER_MAGIC: u64 = 0xBEADC0DE_BEADC0DE;

impl BackPointer {
    unsafe fn get_back_pointer<'a>(
        address: usize,
    ) -> Result<Option<&'a mut LinkedList>, &'static str> {
        let struct_ptr = address
            .checked_sub(BACK_POINTER_SIZE)
            .ok_or_else(|| "invalid pointer")? as *mut Self;
        if struct_ptr.is_null() {
            return Err("invalid pointer");
        }
        if unsafe { (*struct_ptr).magic_number } != BACK_POINTER_MAGIC {
            return Ok(None);
        }
        Ok(Some(unsafe { (*struct_ptr).list_header.as_mut() }))
    }
    unsafe fn make_back_pointer(address: usize, list_address: NonNull<LinkedList>) {
        let header = address as *mut BackPointer;
        unsafe {
            header.write(BackPointer {
                magic_number: BACK_POINTER_MAGIC,
                list_header: list_address,
            });
        }
    }
}

impl LinkedList {
    fn new_node(
        address: usize,
        size: usize,
        prev_header: Option<NonNull<LinkedList>>,
        next_header: Option<NonNull<LinkedList>>,
    ) -> *mut LinkedList {
        let header = address as *mut LinkedList;
        unsafe {
            header.write(LinkedList {
                magic_number: HEADER_MAGIC,
                is_allocated: false,
                prev_header,
                next_header,
                size: size,
            });
        }
        header
    }

    /// Splits the current block if it's large enough, creating a new free block
    /// after the allocated space.
    /// # Safety
    /// This function is unsafe because it performs raw pointer manipulation and assumes
    /// that the provided `end_of_allocation` is a valid address within the block.
    unsafe fn split_block(&mut self, end_of_allocation: usize) -> NonNull<LinkedList> {
        let address = self as *const _ as usize;
        let current_block_end = address + HEADER_SIZE + self.size;

        // If the remaining space is too small for a new block, don't split.
        if current_block_end - end_of_allocation <= HEADER_SIZE {
            return unsafe { NonNull::new_unchecked(self as *mut _) };
        }

        // Create a new free block in the remaining space.
        let next_node = self.next_header;
        let new_node = unsafe {
            NonNull::new_unchecked(Self::new_node(
                end_of_allocation,
                self.size - (end_of_allocation - address),
                Some(NonNull::new_unchecked(self as *mut LinkedList)),
                next_node,
            ))
        };

        // Update the current block to be smaller.
        self.size = end_of_allocation - address - HEADER_SIZE;
        self.next_header = Some(new_node);

        // Update the next block's prev pointer.
        if let Some(mut next_node) = next_node {
            unsafe { next_node.as_mut().prev_header = Some(new_node) };
        }
        new_node
    }

    fn try_allocate(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        if self.is_allocated {
            return None;
        }

        let address = self as *const _ as usize;
        let allocation_size = size.next_multiple_of(HEADER_SIZE);
        let alignment = align.next_multiple_of(HEADER_SIZE);

        let aligned_addr = (address + HEADER_SIZE).next_multiple_of(alignment);
        let end_of_allocation = aligned_addr + allocation_size;

        if end_of_allocation <= address + HEADER_SIZE + self.size {
            self.is_allocated = true;

            let new_node = unsafe { self.split_block(end_of_allocation) };

            // If alignment creates a gap, create a back pointer.
            if aligned_addr != address + HEADER_SIZE {
                unsafe {
                    BackPointer::make_back_pointer(aligned_addr - BACK_POINTER_SIZE, new_node)
                };
            }
            return Some(aligned_addr as *mut u8);
        }

        None
    }

    /// Coalesces this block with adjacent free blocks.
    /// # Safety
    /// This function is unsafe because it performs raw pointer manipulation and assumes
    /// that the linked list is in a valid state.
    unsafe fn coalesce(&mut self) {
        let mut current_header: NonNull<LinkedList> =
            unsafe { NonNull::new_unchecked(self as *mut _) };

        // Coalesce with the next block
        if let Some(next_node) = unsafe { current_header.as_mut().get_next_node() } {
            if !next_node.is_allocated {
                let next_size = next_node.size;
                let next_next = next_node.next_header;
                unsafe {
                    current_header.as_mut().size += HEADER_SIZE + next_size;
                    current_header.as_mut().next_header = next_next;
                    if let Some(mut nn_node) = next_next {
                        nn_node.as_mut().prev_header = Some(current_header);
                    }
                }
            }
        }

        // Coalesce with the previous block
        if let Some(prev_node) = unsafe { current_header.as_mut().get_prev_node() } {
            if !prev_node.is_allocated {
                let current_size = unsafe { current_header.as_mut().size };
                let current_next = unsafe { current_header.as_mut().next_header };
                prev_node.size += HEADER_SIZE + current_size;
                prev_node.next_header = current_next;
                if let Some(mut next_node) = current_next {
                    unsafe {
                        next_node.as_mut().prev_header =
                            Some(NonNull::new_unchecked(prev_node as *mut _));
                    }
                }
            }
        }
    }

    unsafe fn get_header<'a>(address: usize) -> Option<&'a mut Self> {
        let back_pointer = unsafe { BackPointer::get_back_pointer(address) }.unwrap();
        if back_pointer.is_some() {
            return back_pointer;
        }
        let header_ptr = address.checked_sub(HEADER_SIZE)? as *mut Self;
        if header_ptr.is_null() || unsafe { (*header_ptr).magic_number } != HEADER_MAGIC {
            return None;
        }
        unsafe { Self::_get_node(header_ptr) }
    }
    unsafe fn get_next_node<'a>(&self) -> Option<&'a mut Self> {
        if let Some(header) = &self.next_header {
            unsafe { Self::_get_node(header.as_ptr()) }
        } else {
            None
        }
    }
    unsafe fn get_prev_node<'a>(&self) -> Option<&'a mut Self> {
        if let Some(header) = &self.prev_header {
            unsafe { Self::_get_node(header.as_ptr()) }
        } else {
            None
        }
    }
    unsafe fn _get_node<'a>(current_node: *mut Self) -> Option<&'a mut Self> {
        if unsafe { (*current_node).magic_number } != HEADER_MAGIC {
            return None;
        }
        Some(unsafe { &mut *current_node })
    }
}

// This is safe because all access to the linked list is protected by a SpinLock.
pub struct FirstFitAllocator {
    linked_list_head: SpinLock<Option<NonNull<LinkedList>>>,
}

unsafe impl Sync for FirstFitAllocator {}

impl FirstFitAllocator {
    pub fn init_allocator(&self, heap_start: usize, heap_size: usize) {
        let mut linked_list = self.linked_list_head.lock();
        let header_ptr = LinkedList::new_node(heap_start, heap_size - HEADER_SIZE, None, None);
        *linked_list = Some(unsafe { NonNull::new_unchecked(header_ptr) });
    }
    fn allocate_bytes(&self, size: usize, align: usize) -> *mut u8 {
        let alignment = max(align, HEADER_SIZE);
        let mut lock = self.linked_list_head.lock();
        let mut current_node = lock.as_mut().and_then(|ptr| unsafe { Some(ptr.as_mut()) });
        while let Some(node) = current_node {
            let next_node = unsafe { node.get_next_node() };
            if let Some(ptr) = node.try_allocate(size, alignment) {
                return ptr;
            }
            current_node = next_node;
        }
        null_mut::<u8>()
    }
    pub fn free_memory(&self, ptr: usize) {
        let _lock = self.linked_list_head.lock();
        let header = unsafe {
            LinkedList::get_header(ptr).expect("address is not a memory allocated from heap")
        };
        header.is_allocated = false;
        unsafe { header.coalesce() };
    }

    #[cfg(test)]
    fn assert_on_test(&self) {
        let lock = self.linked_list_head.lock();
        let mut current_node = lock.as_ref().and_then(|ptr| unsafe { Some(ptr.as_ref()) });
        while let Some(node) = current_node {
            if let Some(next) = unsafe { node.get_next_node() } {
                assert_eq!(
                    next.prev_header.unwrap().as_ptr(),
                    node as *const _ as *mut _
                );
            }
            if let Some(prev) = unsafe { node.get_prev_node() } {
                assert_eq!(
                    prev.next_header.unwrap().as_ptr(),
                    node as *const _ as *mut _
                );
            }
            current_node = unsafe { node.get_next_node().map(|n| &*n) };
        }
    }
}

#[cfg(not(test))]
#[global_allocator]
pub static ALLOCATOR: FirstFitAllocator = FirstFitAllocator {
    linked_list_head: SpinLock::new(None),
};

unsafe impl GlobalAlloc for FirstFitAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate_bytes(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.free_memory(ptr as usize);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Helper function to set up the allocator for tests
    fn test_setup(heap_size: usize) -> (FirstFitAllocator, Vec<u8>) {
        let allocator = FirstFitAllocator {
            linked_list_head: SpinLock::new(None),
        };
        let mut heap = vec![0; heap_size];
        allocator.init_allocator(heap.as_mut_ptr() as usize, heap.len());
        (allocator, heap)
    }

    #[test]
    fn test_basic_allocation_and_deallocation() {
        let (allocator, _heap) = test_setup(1024);
        for i in 1..10 {
            let layout = Layout::from_size_align(i * 8, 8).unwrap();
            let ptr = unsafe { allocator.alloc(layout) };
            assert!(!ptr.is_null(), "Allocation failed for size {}", i * 8);
            allocator.assert_on_test();
            unsafe { allocator.dealloc(ptr, layout) };
            allocator.assert_on_test();
        }
    }

    #[test]
    fn test_coalescing() {
        let (allocator, _heap) = test_setup(1024);
        let layout1 = Layout::from_size_align(128, 8).unwrap();
        let ptr1 = unsafe { allocator.alloc(layout1) };
        assert!(!ptr1.is_null());
        allocator.assert_on_test();

        let layout2 = Layout::from_size_align(256, 8).unwrap();
        let ptr2 = unsafe { allocator.alloc(layout2) };
        assert!(!ptr2.is_null());
        allocator.assert_on_test();

        let layout3 = Layout::from_size_align(128, 8).unwrap();
        let ptr3 = unsafe { allocator.alloc(layout3) };
        assert!(!ptr3.is_null());
        allocator.assert_on_test();

        // Free in an order that tests coalescing
        unsafe { allocator.dealloc(ptr1, layout1) };
        allocator.assert_on_test();
        unsafe { allocator.dealloc(ptr3, layout3) };
        allocator.assert_on_test();
        unsafe { allocator.dealloc(ptr2, layout2) };
        allocator.assert_on_test();

        // Check if coalescing happened
        let large_layout = Layout::from_size_align(512, 8).unwrap();
        let large_ptr = unsafe { allocator.alloc(large_layout) };
        assert!(
            !large_ptr.is_null(),
            "Large allocation after coalescing failed"
        );
        allocator.assert_on_test();
        unsafe { allocator.dealloc(large_ptr, large_layout) };
    }

    #[test]
    fn test_alignment() {
        let (allocator, _heap) = test_setup(2048);
        let layout_align_64 = Layout::from_size_align(32, 64).unwrap();
        let ptr_align_64 = unsafe { allocator.alloc(layout_align_64) };
        assert!(!ptr_align_64.is_null());
        assert_eq!(ptr_align_64 as usize % 64, 0, "Alignment check failed");
        allocator.assert_on_test();
        unsafe { allocator.dealloc(ptr_align_64, layout_align_64) };
        allocator.assert_on_test();
    }

    #[test]
    fn test_out_of_memory() {
        let (allocator, _heap) = test_setup(2048);
        let layout_oom = Layout::from_size_align(2048, 8).unwrap();
        let ptr_oom = unsafe { allocator.alloc(layout_oom) };
        assert!(
            ptr_oom.is_null(),
            "Allocator should have returned null for OOM"
        );
        allocator.assert_on_test();
    }

    #[test]
    fn test_fragmentation_and_fit() {
        let (allocator, _heap) = test_setup(2048);
        let layout_frag_1 = Layout::from_size_align(64, 8).unwrap();
        let layout_frag_2 = Layout::from_size_align(128, 8).unwrap();
        let layout_frag_3 = Layout::from_size_align(64, 8).unwrap();

        let ptr_frag_1 = unsafe { allocator.alloc(layout_frag_1) };
        assert!(!ptr_frag_1.is_null());
        allocator.assert_on_test();

        let ptr_frag_2 = unsafe { allocator.alloc(layout_frag_2) };
        assert!(!ptr_frag_2.is_null());
        allocator.assert_on_test();

        let ptr_frag_3 = unsafe { allocator.alloc(layout_frag_3) };
        assert!(!ptr_frag_3.is_null());
        allocator.assert_on_test();

        // Free the middle block, creating a hole
        unsafe { allocator.dealloc(ptr_frag_2, layout_frag_2) };
        allocator.assert_on_test();

        // This allocation should fit in the hole
        let layout_fit = Layout::from_size_align(100, 8).unwrap();
        let ptr_fit = unsafe { allocator.alloc(layout_fit) };
        assert!(!ptr_fit.is_null(), "Allocation in fragment failed");
        allocator.assert_on_test();

        // Clean up
        unsafe { allocator.dealloc(ptr_frag_1, layout_frag_1) };
        unsafe { allocator.dealloc(ptr_fit, layout_fit) };
        unsafe { allocator.dealloc(ptr_frag_3, layout_frag_3) };
        allocator.assert_on_test();
    }

    #[test]
    fn test_back_pointer() {
        let (allocator, _heap) = test_setup(2048);
        // Allocate with a large alignment to force a back pointer
        let layout_back_ptr = Layout::from_size_align(32, 256).unwrap();
        let ptr_back_ptr = unsafe { allocator.alloc(layout_back_ptr) };
        assert!(!ptr_back_ptr.is_null());
        assert_eq!(ptr_back_ptr as usize % 256, 0);
        allocator.assert_on_test();
        // Freeing should work correctly
        unsafe { allocator.dealloc(ptr_back_ptr, layout_back_ptr) };
        allocator.assert_on_test();
    }

    #[test]
    fn test_allocation_to_fill_heap() {
        let (allocator, _heap) = test_setup(2048);
        // Final check: the whole heap should be one free block
        let final_layout = Layout::from_size_align(1900, 8).unwrap(); // A bit less than total to account for header
        let final_ptr = unsafe { allocator.alloc(final_layout) };
        assert!(!final_ptr.is_null(), "Final large allocation failed");
        unsafe { allocator.dealloc(final_ptr, final_layout) };
    }
}
