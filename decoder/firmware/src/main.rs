#![no_std]
#![no_main]
pub extern crate max7800x_hal as hal;
use alloc::vec;
use embedded_io::Write;
pub use hal::entry;
pub use hal::pac;

// lib imports
pub extern crate parse_packet as parser;

//print function:
//board.console.write_bytes(b"Hello world\r\n")

use board::Board;

extern crate alloc;
use alloc::format;
use embedded_alloc::LlffHeap as Heap;
use hashbrown::HashMap;
use sha3::{Digest, Sha3_256};
#[global_allocator]
static HEAP: Heap = Heap::empty();

// 16KB heap (adjust based on your needs)
const HEAP_SIZE: usize = 1024 * 32;
static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); HEAP_SIZE];


#[entry]
fn main() -> ! {
    //initialize the board

    unsafe {
        HEAP.init(
            core::ptr::addr_of_mut!(HEAP_MEM).cast::<u8>() as usize,
            HEAP_SIZE,
        );
    }
    let mut board = Board::new();
    board.delay.delay_ms(500);
    board.console.write_bytes(b"Board Initialized\r\n");

    // panic!();
    let is_bit_set = board.is_safety_bit_set();
    board.delay.delay_ms(500);
    if is_bit_set {
        board.console.write_bytes(b"No Lockdown Was Triggerred\r\n");
        board.console.flush().unwrap();
    } else {
        board.lockdown();
    }
    board.delay.delay_ms(1000);
    // panic!();
   


    loop {
        let header: board::host_messaging::Header = board::host_messaging::read_header(&mut board);
        match header.opcode {
            board::host_messaging::Opcode::List => {
                board::host_messaging::list_subscriptions(&mut board);
            }
            board::host_messaging::Opcode::Subscribe => {

                board::host_messaging::subscription_update(&mut board, header);
            }
            _ => {
                panic!()
            }
        }
    }
    // panic!();
}
