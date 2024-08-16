use crate::PL011;
use crate::UART_DR;
use crate::UART_FR;

static mut random:u8 = 0;
static mut ignore_esc: usize = 0;

pub fn set_color(color: u8) {
    putc_free(0x1b);//ESC
    match color {
        0 => put_free("[39m"),//default
        1 => put_free("[30m"),//black
        2 => put_free("[31m"),//red
        3 => put_free("[32m"),//green
        4 => put_free("[33m"),//yellow
        5 => put_free("[34m"),//blue
        6 => put_free("[35m"),//magenta
        7 => put_free("[36m"),//cyan
        8 => put_free("[37m"),//white
        9 => put_free("[0m"),//background default
        10 => put_free("[1m"),//emphasis
        11 => put_free("[4m"),//underbar
        12 => put_free("[7m"),//inverse
        _ => unimplemented!(),
    }
}

pub fn put(input: &str) {
    for i in input.chars() {
        putc(i as u8);
    }
}

pub fn put_free(input: &str) {
    for i in input.chars() {
        putc_free(i as u8);
    }
}

pub fn putc_free(c: u8) {
    if c == b'\n' {
        loop_write_char(b'\r');
    }
    loop_write_char(c);
}

/// put char PL011
pub fn putc(c: u8) {
    /*if c == 0x1b {
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
        loop_write_char(b'\r');
    }
    loop_write_char(c);
}

fn loop_write_char(c: u8) {
    loop{
        if is_write_fifo_full() == false {
            write_char(c);
            break;
        }
    }
}

fn write_char(c: u8) {
    unsafe { core::ptr::write_volatile((PL011 + UART_DR) as *mut u8, c) };
}

fn is_write_fifo_full() -> bool {
    (unsafe { core::ptr::read_volatile((PL011 + UART_FR) as *const u16) } & (1 << 5)) != 0
}