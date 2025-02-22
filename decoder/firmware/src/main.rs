#![no_std]
#![no_main]
pub extern crate max7800x_hal as hal;
use alloc::vec;
use board::host_messaging;
use board::host_messaging::send_debug_message;
use embedded_io::Write;
pub use hal::entry;
pub use hal::pac;
use hal::pac::adc::limit::W;
use segtree_kdf;
use board::SHA256Hasher;

include!(concat!(env!("OUT_DIR"), "/secrets.rs"));
// this comment is useless, added by nithin.

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
const HEAP_SIZE: usize = 1024 * 16;
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

    if let Some(val) = get_key("K1") {
        write!(board.console, "Key K1: {:?}\r\n", val).unwrap();
    }
    // let size = size_of::<segtree_kdf::SegtreeKDF::<SHA256Hasher>>();
    // board::host_messaging::send_debug_message(&mut board, &format!("Size of SegtreeKDF: {}", size));
    loop {
        let header: board::host_messaging::Header = board::host_messaging::read_header(&mut board);
        match header.opcode {
            board::host_messaging::Opcode::List => {
                board::host_messaging::list_subscriptions(&mut board);
            }
            board::host_messaging::Opcode::Subscribe => {
                let mut data = [0u8; 5120];
                let length = header.length.clone();
                board::host_messaging::subscription_update(&mut board, header, &mut data[0..length as usize]);
                let key = get_key("Ks").unwrap();
                host_messaging::send_debug_message(&mut board, "Worked broooooo");

                if let Some(subscription) = board::decrypt_data::decrypt_sub(&mut board, &mut data[0..length as usize], *key){
                    host_messaging::send_debug_message(&mut board, "Worked broooooo till decrypt sub");
                    board.subscriptions.add_subscription(subscription);  
                    // host_messaging::succesful_subscription(&mut board);
                    host_messaging::send_debug_message(&mut board, "Worked broooooo till the end");

                }
                else{
                    board::host_messaging::send_debug_message(&mut board, "Invalid Subscription Received");
                }
            }
            _ => {
                panic!()
            }
        }
    }
    // panic!();
}
