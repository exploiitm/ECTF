#![no_std]
#![no_main]

extern crate alloc;
use crate::alloc::collections::BTreeMap;

use board::MAX_SUBSCRIPTION_SIZE;
use embedded_alloc::LlffHeap as Heap;
use hmac::{Hmac, Mac};
use sha3::Sha3_256;
type HmacSha = Hmac<Sha3_256>;

use board::decrypt_data;
use board::host_messaging;
use board::parse_packet::parse_packet;
use board::Board;
use board::ChannelFlashMap;
use hal::entry;
use hal::flc::FlashError;
use max7800x_hal as hal;

// Include secrets
include!(concat!(env!("OUT_DIR"), "/secrets.rs"));

#[global_allocator]
static HEAP: Heap = Heap::empty();

// 16KB heap
const HEAP_SIZE: usize = 1024 * 16;
static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); HEAP_SIZE];

#[entry]
fn main() -> ! {
    //initializing heap
    unsafe {
        HEAP.init(
            core::ptr::addr_of_mut!(HEAP_MEM).cast::<u8>() as usize,
            HEAP_SIZE,
        );
    }

    //initializing board
    let mut board = Board::new();
    board.delay.delay_ms(500);

    let lockdown_bit = board.is_safety_bit_set();
    board.delay.delay_ms(500);

    if !lockdown_bit {
        board.lockdown();
    }
    board.delay.delay_ms(1000);

    let mut channel_map = board.read_channel_map().unwrap_or(ChannelFlashMap {
        map: BTreeMap::new(),
    });

    // Retrieve all the subscriptions from flash and decrupt them
    for (&_channel_id, &page_addr) in channel_map.map.iter() {
        let mut data = [0u8; MAX_SUBSCRIPTION_SIZE];

        // Read each sub from flash
        if let Ok(length) = board.read_sub_from_flash(page_addr, &mut data) {
            let key = get_key("Ks").unwrap();

            // Decrypt the subscription and subscribe again to the file
            decrypt_data::decrypt_sub(&mut data[0..length as usize], *key, DECODER_ID)
                .map(|subscription| {
                    board.subscriptions.add_subscription(subscription);
                })
                .unwrap();
        }
    }

    let mut most_recent_timestamp = None;

    // receive opcodes
    loop {
        let header = board::host_messaging::read_header(&mut board);

        match header.opcode {
            board::host_messaging::Opcode::List => {
                board::host_messaging::list_subscriptions(&mut board);
            }

            board::host_messaging::Opcode::Subscribe => {
                match subscribe(&header, &mut board, &mut channel_map) {
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }

            board::host_messaging::Opcode::Decode => {
                decode(&header, &mut board, &mut most_recent_timestamp)
            }
            _ => {
                panic!("Unknown opcode")
            }
        }
    }
}

fn subscribe(
    header: &host_messaging::Header,
    board: &mut Board,
    channel_map: &mut ChannelFlashMap,
) -> Result<(), FlashError> {
    let mut data = [0u8; MAX_SUBSCRIPTION_SIZE];
    let length = header.length.clone();
    board::host_messaging::subscription_update(board, header, &mut data[0..length as usize]);

    // Find a new available page for the subscription update
    let address = board.find_available_page()?;
    board.delay.delay_ms(500);

    // Write the subscription to the assigned page in flash
    board
        .write_sub_to_flash(address, &mut data[0..length as usize])
        .unwrap();

    // Attempt decryption of the subscription
    let key = get_key("Ks").unwrap();
    decrypt_data::decrypt_sub(&mut data[0..length as usize], *key, DECODER_ID)
        .map(|subscription| {
            let channel_id = subscription.channel;

            // Rewriting the subscription flash map dictionary
            board
                .assign_page_for_subscription(channel_map, channel_id, address)
                .unwrap();
            board.subscriptions.add_subscription(subscription);
            host_messaging::succesful_subscription(board);
        })
        .unwrap();
    board.delay.delay_ms(2000);
    Ok(())
}

fn decode(
    header: &host_messaging::Header,
    board: &mut Board,
    most_recent_timestamp: &mut Option<u64>,
) {
    let length = header.length;
    if length != 125 {
        panic!("length mismatch in decode");
    }

    let mut frame_data = [0u8; 125];
    board::host_messaging::read_frame_packet(board, header, &mut frame_data);
    let packet = parse_packet(&frame_data);
    let mut sub_index = None;
    board.delay.delay_ms(500);

    let key = if packet.channel_id == 0 {
        get_key("K0").unwrap()
    } else {
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

        &board.subscriptions.subscriptions[sub_index.unwrap() as usize]
            .as_ref()
            .unwrap()
            .kdf
            .derive(packet.timestamp)
            .unwrap()
    };

    if let Some(rec) = most_recent_timestamp {
        if packet.timestamp < *rec {
            panic!("timestamp reversion in decode");
        }
    }
    *most_recent_timestamp = Some(packet.timestamp);

    let mut hmac = HmacSha::new_from_slice(key).unwrap();
    hmac.update(&frame_data[..93]);
    let result = hmac.finalize().into_bytes();

    let mut comparison = 0;
    for byte_tuple in result.iter().zip(&frame_data[93..]) {
        // host_messaging::send_debug_message(&mut board, "HMAC FAILED NOW");
        comparison |= byte_tuple.0 ^ byte_tuple.1;
    }

    if comparison != 0 {
        panic!("hmacs failure in decode");
    }

    let mut result: [u8; 64] = [0u8; 64];
    decrypt_data::decrypt_data(&packet.data_enc, &key, &packet.iv, &mut result);
    let result = &result[0..packet.length as usize];
    host_messaging::write_decoded_packet(board, result);
}
