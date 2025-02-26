#![no_std]
#![no_main]
pub extern crate max7800x_hal as hal;
use core::fmt::write;

use crate::alloc::string::ToString;
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
use board::ChannelFlashMap; // Struct holding flash information

use alloc::collections::BTreeMap; // The channel flash map
use alloc::format;
use embedded_alloc::LlffHeap as Heap;
use sha3::Digest;

type HmacSha = Hmac<Sha3_256>;

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
    // First, load the channel to location mapping dictionary
    // Next, retrieve data from each of the mapped pages in flash
    // Finally, process each of those retrieved pages and add subscriptions after getting Ks

    // Reconstructs the channel map if it exists, else is new
    let mut channel_map = board.read_channel_map().unwrap_or(ChannelFlashMap {
        map: BTreeMap::new(),
    });

    // Retrieve all the subscriptions from flash and decrupt them
    for (&channel_id, &page_addr) in channel_map.map.iter() {
        let mut data = [0u8; 5120];

        // Read each sub from flash
        if let Ok(_) = board.read_sub_from_flash(page_addr, &mut data) {
            host_messaging::send_debug_message(
                &mut board,
                &format!(
                    "Subscription found for Channel {} at 0x{:X}",
                    channel_id, page_addr
                ),
            );

            let key = get_key("Ks").unwrap();

            // Decrypt the subscription and subscribe again to the file
            if let Some(subscription) =
                board::decrypt_data::decrypt_sub(&mut board, &mut data, *key)
            {
                board.subscriptions.add_subscription(subscription);
                host_messaging::send_debug_message(
                    &mut board,
                    &format!("Subscription for Channel {} loaded", channel_id),
                );
            } else {
                host_messaging::send_debug_message(&mut board, "Error decrypting subscription");
            }
        } else {
            host_messaging::send_debug_message(
                &mut board,
                &format!("Failed to read subscription for Channel {}", channel_id),
            );
        }
    }

    // TODO: Decide on behavior of this part of the code after panic
    // Essentially implement the wipe flash methods in panics

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
                host_messaging::send_debug_message(
                    &mut board,
                    &format!("Header length: {}", length),
                );
                board::host_messaging::subscription_update(
                    &mut board,
                    header,
                    &mut data[0..length as usize],
                );
                let key = get_key("Ks").unwrap();
                // Find a new available page for the subscription update
                let address = match board.find_available_page() {
                    Ok(addr) => addr,
                    Err(_) => {
                        host_messaging::send_debug_message(&mut board, "No available page found");
                        continue;
                    }
                };

                board.delay.delay_ms(500);
                // Write the subscription to the assigned page in flash
                let result = board.write_sub_to_flash(address, &mut data[0..length as usize]);
                match result {
                    Ok(_) => {
                        host_messaging::send_debug_message(
                            &mut board,
                            "Subscription written to flash",
                        );
                    }
                    Err(_) => {
                        host_messaging::send_debug_message(&mut board, "Error writing to flash");
                    }
                }
                // Attempt decryption of the subscription
                if let Some(subscription) = board::decrypt_data::decrypt_sub(
                    &mut board,
                    &mut data[0..length as usize],
                    *key,
                ) {
                    let channel_id = subscription.channel;

                    // Rewriting the subscription flash map dictionary
                    board.assign_page_for_subscription(&mut channel_map, channel_id, address);
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
                    0 => get_key("K0").unwrap(),
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

                        &board.subscriptions.subscriptions[sub_index.unwrap() as usize]
                            .as_ref()
                            .unwrap()
                            .kdf
                            .derive(packet.timestamp)
                            .unwrap()
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

                if !result
                    .iter()
                    .zip(&frame_data[93..])
                    .all(|bytes| bytes.0 == bytes.1)
                {
                    // host_messaging::send_debug_message(&mut board, "HMAC FAILED NOW");
                    panic!("Suck my dick")
                }

                // host_messaging::send_debug_message(&mut board, "HMAC PASSED NIGGERS");
                let mut result: [u8; 64] = [0u8; 64];
                board::decrypt_data::decrypt_data(&packet.data_enc, &key, &packet.iv, &mut result);
                // host_messaging::send_debug_message(&mut board, &format!("Decrypted data: {:?}", result ));
                let result = &result[0..packet.length as usize];

                host_messaging::write_decoded_packet(&mut board, result);
            }
            _ => {
                panic!()
            }
        }
    }
    // panic!();
}
