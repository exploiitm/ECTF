#![no_std]
use alloc::fmt::format;
use alloc::string::ToString;
use cipher::block_padding::{NoPadding, Pkcs7};
use cipher::consts::U16;
extern crate alloc;
use alloc::vec;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
use alloc::format;

use crate::{Board, host_messaging};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct Subscription {
    //    subscription_data = device_id_bytes + \
    //    channel_bytes + start_bytes + end_bytes + key_data
    device_id_bytes: [u8; 4],
    channel_bytes: [u8; 4],
    start_bytes: u64,
    end_bytes: u64,
    key_data: vec::Vec<u8>,
}

fn decrypt_data(data_enc: &[u8; 64], key: &[u8; 32], iv: &[u8; 16]) -> vec::Vec<u8> {
    Aes256CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_padded_vec_mut::<NoPadding>(data_enc)
        .unwrap()
}

pub fn decrypt_sub(board: &mut Board, encrypted_sub: vec::Vec<u8>, key: [u8; 64]) -> ! {

    host_messaging::send_debug_message(board, "Decrypting Subscription");
    let debug_msg = format!("The length is {:?}", encrypted_sub.len());
    host_messaging::send_debug_message(board, &debug_msg);


    let iv = GenericArray::from_slice(&encrypted_sub[0..16]);
    let mut ciphertext = &encrypted_sub[16..].to_vec();
    host_messaging::send_debug_message(board, "breakpoint 1 ");
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    let hard_device_id: u32 = 0xdeadbeef;
    let hard_device_id = hard_device_id.to_string();

    hasher.update(hard_device_id);
    host_messaging::send_debug_message(board, "breakpoint 2 ");
    let k10 = hasher.finalize();
    host_messaging::send_debug_message(board, "breakpoint 3 ");
    // let k10 = GenericArray::from_slice(&k10);
    let debug_msg = format!("The decryption key is {:?}", k10);
    host_messaging::send_debug_message(board, &debug_msg);
    let debug_msg = format!("The iv  is {:?}", iv.clone());
    host_messaging::send_debug_message(board, &debug_msg);
    let debug_msg = format!("The ciphertext  is {:?}", ciphertext.clone());
    host_messaging::send_debug_message(board, &debug_msg);
    let k10_new = GenericArray::from_slice(&k10);
    let mut decrypted_data = Aes256CbcDec::new(k10_new, iv);
    let mut decrypted_data = decrypted_data.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).unwrap();
    host_messaging::send_debug_message(board, "breakpoint 4 ");
    //
    let length_bytes = &decrypted_data[0..8]; 
    let device_id_bytes = &decrypted_data[8..12];
    // // Remaining bytes are key_data
    // let key_data = decrypted_data.split_off(24);
    /*
    Some(Packet {
        magic,
        timestamp: u64::from_le_bytes(timestamp_bytes),
        channel_id: u32::from_le_bytes(channel_id_bytes),
        data_enc,
        hmac,
        end_magic,
        }) */
    host_messaging::send_debug_message(board, &format!("device id {:?}", device_id_bytes));
    // Some(Subscription {
    //     device_id_bytes,
    //     channel_bytes,
    //     start_bytes,
    //     end_bytes,
    //     key_data,
    // })
    loop {}
}
