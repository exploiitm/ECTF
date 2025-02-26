#![no_std]
use alloc::fmt::format;
use alloc::string::ToString;
use cipher::block_padding::{NoPadding, Pkcs7};
use cipher::consts::U16;
extern crate alloc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
use alloc::format;
use alloc::vec;
use hmac::{Hmac, Mac};
use max7800x_hal::pac::dma::ch;

use crate::{Board, host_messaging};
use sha3::{Digest, Sha3_256};

type HmacSha = Hmac<Sha3_256>;

use crate::Subscription;
pub fn decrypt_data(data_enc: &[u8; 64], key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8; 64]) {
    let data = Aes256CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_padded_vec_mut::<NoPadding>(data_enc)
        .unwrap();
    buf.copy_from_slice(&data);
}

pub fn decrypt_sub(
    board: &mut Board,
    encrypted_sub: &[u8],
    key: [u8; 32],
    device_id: u32,
) -> Option<Subscription> {
    host_messaging::send_debug_message(
        board,
        &format!("encrypted sub length: {}", encrypted_sub.len()),
    );
    let iv = GenericArray::from_slice(&encrypted_sub[0..16]);
    let ciphertext = &encrypted_sub[16..(encrypted_sub.len() - 32)];

    host_messaging::send_debug_message(board, "b1");
    host_messaging::send_debug_message(board, &format!("see key and check bro {:x?}", key));
    let k10_new = GenericArray::from_slice(&key);
    let decryptor = Aes256CbcDec::new(k10_new, iv);
    let decrypted_data = decryptor
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .unwrap();
    //

    host_messaging::send_debug_message(board, "b2");
    let hmac_received = &encrypted_sub[(encrypted_sub.len() - 32)..];

    // TODO: get key for hmac
    let mut hmac = HmacSha::new_from_slice(&key).unwrap();

    host_messaging::send_debug_message(board, "b3");
    hmac.update(&encrypted_sub[..(encrypted_sub.len() - 32)]);
    host_messaging::send_debug_message(board, "b4");
    let result = hmac.finalize();

    host_messaging::send_debug_message(board, "b4");
    let mut comparison = 0;
    let result = result.into_bytes();

    host_messaging::send_debug_message(board, "b4");
    for byte_tuple in result.iter().zip(hmac_received) {
        comparison |= byte_tuple.0 ^ byte_tuple.1;
    }

    if comparison != 0 {
        panic!();
    }

    host_messaging::send_debug_message(board, "b5");
    host_messaging::send_debug_message(board, "Decryption of data worked in decrypt_sub");
    let length_bytes: [u8; 8] = decrypted_data[0..8].try_into().unwrap();
    let device_id_bytes: [u8; 4] = decrypted_data[8..12].try_into().unwrap();
    let channel_bytes: [u8; 4] = decrypted_data[12..16].try_into().unwrap();
    let start_bytes: [u8; 8] = decrypted_data[16..24].try_into().unwrap();
    let end_bytes: [u8; 8] = decrypted_data[24..32].try_into().unwrap();

    host_messaging::send_debug_message(
        board,
        &format!("Your momma so fat, le couldn't handle her"),
    );
    host_messaging::send_debug_message(
        board,
        &format!(
            "Length written in sub: {}",
            u64::from_le_bytes(length_bytes)
        ),
    ); //u64::from_le_bytes(length_bytes)
    let key_data = &decrypted_data[32..u64::from_le_bytes(length_bytes) as usize + 8 /* length of the length bytes */];
    let device_id_received = u32::from_le_bytes(device_id_bytes);
    let channel = u32::from_le_bytes(channel_bytes);
    let start = u64::from_le_bytes(start_bytes);
    let end = u64::from_le_bytes(end_bytes);

    host_messaging::send_debug_message(
        board,
        &format!("device id received is {:x}", device_id_received),
    );
    host_messaging::send_debug_message(board, &format!("device id inherent  is {:x}", device_id));
    if device_id != device_id_received {
        host_messaging::send_debug_message(board, &format!("device id does not match"));
        return None;
    }

    host_messaging::send_debug_message(board, &format!("device id {:x?}", &decrypted_data[0..10]));
    let subscription = Subscription::new(channel, start, end, key_data);
    host_messaging::send_debug_message(board, "created subs obj.");
    Some(subscription)
}
