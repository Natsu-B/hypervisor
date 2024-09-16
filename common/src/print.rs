use crate::print;
use crate::println;
use crate::PL011_QEMU;
use crate::SERIAL_PORT;
use crate::UART_DR;
use crate::UART_FR;

pub fn set_color(color: u8) {
    putc_check(0x1b); //ESC
    match color {
        0 => put("[39m"), //default
        1 => put("[30m"), //black
        2 => put("[31m"), //red
        3 => put("[32m"), //green
        4 => put("[33m"), //yellow
        5 => put("[34m"), //blue
        6 => put("[35m"), //magenta
        7 => put("[36m"), //cyan
        8 => put("[37m"), //white
        9 => put("[0m"),  //background default
        10 => put("[1m"), //emphasis
        11 => put("[4m"), //underbar
        12 => put("[7m"), //inverse
        _ => unimplemented!(),
    }
}

pub fn put(input: &str) {
    if let Some(serial_port) = unsafe { SERIAL_PORT } {
        for i in input.chars() {
            putc(i as u8, serial_port);
        }
    } else {
        unsafe { SERIAL_PORT = Some(PL011_QEMU) };
        println!("Can't detect PL011 but used");
        println!("This print assumes that this program is run by a Qemu virt device...");
        put(input);
        panic!();
    }
}

// put char PL011
// This does not check that SERIAL_PORT is not None, if you want to use this alone use putc_check.
fn putc(c: u8, serial_port: usize) {
    /* //Remove ANSI Escape sequence
    if c == 0x1b {
        unsafe {
            ignore_esc = 1;
        }
    } else if unsafe { ignore_esc == 1 } && c == b'[' {
        unsafe {
            ignore_esc = 2;
        }
    } else if unsafe { ignore_esc == 2 } {
        if (0x40..=0x7E).contains(&c) {
            unsafe {
                ignore_esc = 0;
            }
        } //ここまでcolorコードの対処
    } else {
        unsafe{random = random.overflowing_add(1).0;}
        putc_free(0x1b);
        unsafe{print!("[38;5;{}m",random)};
        putc_free(0x1b);
        unsafe{print!("[48;5;{}m",255-random)};
    }*/
    if c == b'\n' {
        loop_write_char(b'\r', serial_port);
    }
    loop_write_char(c, serial_port);
}

pub fn putc_check(c: u8) {
    if let Some(serial_port) = unsafe { SERIAL_PORT } {
        putc(c as u8, serial_port);
    } else {
        unsafe { SERIAL_PORT = Some(PL011_QEMU) };
        println!("Can't detect PL011 but used");
        println!("This print assumes that this program is run by a Qemu virt device...");
        putc(c as u8, PL011_QEMU);
        panic!();
    }
}

fn loop_write_char(c: u8, serial_port: usize) {
    loop {
        if is_write_fifo_full(serial_port) == false {
            write_char(c, serial_port);
            break;
        }
    }
}

fn write_char(c: u8, serial_port: usize) {
    unsafe { core::ptr::write_volatile((serial_port + UART_DR) as *mut u8, c) };
}

fn is_write_fifo_full(serial_port: usize) -> bool {
    (unsafe { core::ptr::read_volatile((serial_port + UART_FR) as *const u16) } & (1 << 5)) != 0
}
