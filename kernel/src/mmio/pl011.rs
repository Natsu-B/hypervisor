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

use core::panic;

use common::print::putc_check;
use common::{SERIAL_PORT, UART_DR, UART_FR};

pub fn mmio_read(offset: usize, _access_width: u64) -> Result<u64, ()> {
    if let Some(pl011) = unsafe {SERIAL_PORT} {
        let data = unsafe { core::ptr::read_volatile((pl011 + offset) as *mut u32) as u64 };
        Ok(data)
    }else{panic!();}
}

pub fn mmio_write(offset: usize /*, _access_width: u64*/, value: u64) -> Result<(), ()> {
    //println!("{:#X}",value);
    match offset {
        UART_DR => {
            putc_check(value as u8);
            Ok(())
        }
        _ => {
            if let Some(pl011) = unsafe { SERIAL_PORT } {
                unsafe {
                    core::ptr::write_volatile((pl011 + offset) as *mut u32, value as u32);
                }
            } else {
                panic!();
            }
            Ok(())
        }
    }
}
