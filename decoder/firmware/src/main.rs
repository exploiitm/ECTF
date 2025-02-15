#![no_std]
#![no_main]
pub extern crate max7800x_hal as hal;
use alloc::vec;
use embedded_io::Write;
pub use hal::entry;
pub use hal::pac;
// this comment is useless, added by nithin.

// use core::cell::RefCell;

// use cortex_m::interrupt::{self, Mutex};

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

// fn derive_key(
//     timestamp: u64, // Now 64-bit
//     cover: &HashMap<u128, [u8; 32]>,
//     left_salt: &[u8; 32],
//     right_salt: &[u8; 32],
// ) -> [u8; 32] {
//     // If the full timestamp is in cover, return its key directly
//     let mut iterator: u128 = u128::from(timestamp) + (1u128 << 64 - 1);
//
//     if let Some(key) = cover.get(&iterator) {
//         return *key;
//     }
//
//     // Work backwards until we find a prefix in the cover
//     let mut salts_to_apply = 1u128;
//
//     while iterator > 0 {
//         salts_to_apply <<= 1;
//         salts_to_apply |= iterator & 1;
//         iterator >>= 1;
//
//         if let Some(cover_key) = cover.get(&iterator) {
//             // Found a cover key, now derive forward
//             let mut current_key = *cover_key;
//
//             while salts_to_apply != 1 {
//                 let mut hasher = Sha256::new();
//                 hasher.update(&current_key);
//                 if salts_to_apply & 1 == 1 {
//                     // Apply right salt
//                     hasher.update(right_salt);
//                     current_key = hasher.finalize().into();
//                 } else {
//                     hasher.update(left_salt);
//                     current_key = hasher.finalize().into();
//                 }
//             }
//
//             return current_key;
//         }
//     }
//
//     panic!("No valid cover key found for timestamp");
// }

fn test_key_derivation(board: &mut Board) {
    // Set up example cover and salts with fixed 32-byte arrays
    board.console.write_bytes(b"breakpoint 1\r\n");
    let mut cover = HashMap::new();

    board.console.write_bytes(b"breakpoint 2\r\n");
    // Example cover keys (32 bytes each)
    cover.insert("nigger", [0u8; 32]).unwrap(); // Cover for timestamps starting with 0
                                                // cover.insert(foo, [2u8; 32]); // Cover for timestamps starting with 10
                                                // cover.insert(110, [3u8; 32]); // Cover for timestamps starting with 110

    // let left_salt = [4u8; 32]; // 32-byte left salt
    // let right_salt = [5u8; 32]; // 32-byte right salt

    board.console.write_bytes(b"breakpoint 3\r\n");
    // Test some full 64-bit timestamps
    // let test_timestamps = vec![
    //     0x0000000000000001, // Timestamp starting with 0
    //     0x4000000000000000, // Timestamp starting with 01
    //     0x0000000000000001, // Timestamp starting with 0
    //     0x8000000000000000, // Timestamp starting with 1
    //     0xC000000000000000, // Timestamp starting with 11
    //     0xD000000000000000, // Invalid timestamp
    // ];

    // for ts in test_timestamps {
    //     let _key = derive_key(ts, &cover, &left_salt, &right_salt);
    // }
    board.console.write_bytes(b"breakpoint 4\r\n");
}

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

    let var = 0x69;
    let string = alloc::format!("Value of var is: {}\r\n", var);
    board.console.write_bytes(string.as_bytes());
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
    let mut cover = HashMap::new();
    write!(board.console, "Made Hash Map\r\n").unwrap();
    cover.insert("nigger", [1u8; 32]);
    write!(board.console, "updated Hash Map\r\n").unwrap();

    write!(board.console, "hash creation\r\n").unwrap();
    let mut hasher = Sha3_256::new();
    write!(board.console, "hash creation success\r\n").unwrap();
    hasher.update(b"nigger");
    write!(board.console, "hash update success\r\n").unwrap();
    let result = hasher.finalize();
    write!(board.console, "hash finalize success\r\n").unwrap();

    loop {
        let header: board::host_messaging::Header = board::host_messaging::read_header(&mut board);
        match header.opcode {
            board::host_messaging::Opcode::List => {
                board::host_messaging::list_subscriptions(&mut board);
            }
            board::host_messaging::Opcode::Decode => {
                board::host_messaging::decode(&mut board, header);
            }
            _ => {
                panic!()
            }
        }
    }
    // panic!();
}
