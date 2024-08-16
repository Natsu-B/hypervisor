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

use crate::print::set_color;

use core::panic;

use crate::print::putc;
use crate::PL011;
use crate::UART_DR;
use crate::UART_FR;

pub fn mmio_read(offset: usize, _access_width: u64) -> Result<u64, ()> {
    let data = unsafe { core::ptr::read_volatile((PL011 + offset) as *mut u32) as u64 };
    Ok(data)
}

pub fn mmio_write(offset: usize /*, _access_width: u64*/, value: u64) -> Result<(), ()> {
    //println!("{:#X}",value);
    match offset {
        UART_DR => {
            putc(value as u8);
            Ok(())
        }
        _ => {
            unsafe {
                core::ptr::write_volatile((PL011 + offset) as *mut u32, value as u32);
            }
            Ok(())
        }
    }
}
