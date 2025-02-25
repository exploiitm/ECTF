#![no_std]
#![no_main]
pub extern crate max7800x_hal as hal;
use core::fmt::write;

use alloc::vec;
use board::decrypt_data;
use board::host_messaging;
use board::host_messaging::send_debug_message;
use board::SHA256Hasher;
use board::Subscriptions;
use embedded_io::Write;
pub use hal::entry;
pub use hal::pac;
use hal::pac::adc::limit::W;
use hmac::{Hmac, Mac};
use parse_packet::parse_packet;
use sha3::Sha3_256;

extern crate alloc;
// use alloc::vec;

use segtree_kdf::{self, Key, KeyHasher, MAX_COVER_SIZE};
include!(concat!(env!("OUT_DIR"), "/secrets.rs"));
// this comment is useless, added by nithin.

//print function:
//board.console.write_bytes(b"Hello world\r\n")

use board::Board;

use alloc::format;
use embedded_alloc::LlffHeap as Heap;
use sha3::{Digest, };

type HmacSha = Hmac<Sha3_256>;

#[global_allocator]
static HEAP: Heap = Heap::empty();

// 16KB heap (adjust based on your needs)
const HEAP_SIZE: usize = 1024 * 64;
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


    // let size = size_of::<segtree_kdf::SegtreeKDF::<SHA256Hasher>>();
    // board::host_messaging::send_debug_message(&mut board, &format!("Size of SegtreeKDF: {}", size));
    let mut most_recent_timestamp = None;
    loop {
        let header: board::host_messaging::Header = board::host_messaging::read_header(&mut board);
        match header.opcode {
            board::host_messaging::Opcode::List => {
                board::host_messaging::list_subscriptions(&mut board);
            }
            board::host_messaging::Opcode::Subscribe => {
                let mut data = [0u8; 5120];
                let length = header.length.clone();
                host_messaging::send_debug_message(&mut board, &format!("Header length: {}", length));
                board::host_messaging::subscription_update(
                    &mut board,
                    header,
                    &mut data[0..length as usize],
                );
                let key = get_key("Ks").unwrap();

                if let Some(subscription) = board::decrypt_data::decrypt_sub(
                    &mut board,
                    &mut data[0..length as usize],
                    *key,
                ) {
                    board.subscriptions.add_subscription(subscription);
                    host_messaging::succesful_subscription(&mut board);

                } else {
                    board::host_messaging::send_debug_message(
                        &mut board,
                        "Invalid Subscription Received",
                    );

                }
                board.delay.delay_ms(2000);

            }
            board::host_messaging::Opcode::Decode => {
                let length = header.length;
                if length != 125 {
                    panic!("Arivoli is black");
                }
                let mut frame_data = [0u8; 125];
                board::host_messaging::read_frame_packet(&mut board, header, &mut frame_data);
                let packet = parse_packet(&frame_data);
                let mut sub_index = None;
                board.delay.delay_ms(500);

                let key = match packet.channel_id {
                    0 => {
                        get_key("K0").unwrap()
                    }, 
                    _ => {
                        for index in 0..board.subscriptions.size {
                            if board.subscriptions.subscriptions[index as usize]
                                .as_ref()
                                .unwrap()
                                .channel
                                == packet.channel_id
                            {
                                sub_index = Some(index);
                                break;
                            }
                        }
                        
                        // host_messaging::send_debug_message(&mut board, &format!("{:?}", sub_index));
                        // host_messaging::send_debug_message(&mut board, "Found subscription");
                        
                        &board
                            .subscriptions
                                .subscriptions[sub_index.unwrap() as usize]
                                    .as_ref().unwrap()
                                    .kdf.derive(packet.timestamp).unwrap()
                    }
                };

                if let Some(rec) = most_recent_timestamp {
                    if packet.timestamp < rec {
                        // host_messaging::send_debug_message(&mut board, "Timestamp is too old");
                        panic!("lol nigger");
                    }
                }
                most_recent_timestamp = Some(packet.timestamp);
                // host_messaging::send_debug_message(&mut board, "break3");

                // host_messaging::send_debug_message(&mut board, &format!("{:?}", key));

                let mut hmac = HmacSha::new_from_slice(key).unwrap();

                hmac.update(&frame_data[..93]);
                let result = hmac.finalize().into_bytes();


                // host_messaging::send_debug_message(&mut board, &format!("here is the unsigned frame nigger, {:?}", &frame_data[0..10]));
                // host_messaging::send_debug_message(&mut board, &format!("here is the unsigned frame nigger, {:?}", &frame_data[83..93]));
                // host_messaging::send_debug_message(&mut board, &format!("here is the hmac nigger, {:?}", result));
                if !result
                    .iter()
                    .zip(&frame_data[93..])
                    .all(|bytes| bytes.0 == bytes.1)
                {
                    // host_messaging::send_debug_message(&mut board, "HMAC FAILED NOW");
                    panic!("Suck my dick")
                }

                // host_messaging::send_debug_message(&mut board, "HMAC PASSED NIGGERS");
                let mut result: [u8;64] = [0u8; 64];
                board::decrypt_data::decrypt_data(
                    &packet.data_enc,
                    &key,
                    &packet.iv,
                    &mut result
                );
                // host_messaging::send_debug_message(&mut board, &format!("Decrypted data: {:?}", result ));
                let result = &result[0..packet.length as usize];

                host_messaging::write_decoded_packet(&mut board, result); 

                // TODO verify above
            }
            _ => {
                panic!()
            }
        }
    }
    // panic!();
}

