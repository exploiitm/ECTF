#![no_std]
use cipher::block_padding::NoPadding;
use cipher::consts::U16;
extern crate alloc;
use alloc::vec;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

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
    Aes128CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_padded_vec_mut::<NoPadding>(data_enc)
        .unwrap()
}

pub fn decrypt_sub(encrypted_sub: vec::Vec<u8>, key: [u8; 32]) -> Option<Subscription> {
    let iv = GenericArray::from_slice(&encrypted_sub[0..16]);
    let ciphertext = &encrypted_sub[16..];
    let key = GenericArray::from_slice(&key);

    let mut decrypted_data = Aes128CbcDec::new(key, iv)
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .unwrap();
    let device_id_bytes = [
        decrypted_data[0],
        decrypted_data[1],
        decrypted_data[2],
        decrypted_data[3],
    ];
    let channel_bytes = [
        decrypted_data[4],
        decrypted_data[5],
        decrypted_data[6],
        decrypted_data[7],
    ];

    let start_bytes = u64::from_le_bytes(decrypted_data[8..16].try_into().unwrap());
    let end_bytes = u64::from_le_bytes(decrypted_data[16..24].try_into().unwrap());

    // Remaining bytes are key_data
    let key_data = decrypted_data.split_off(24);
    /*
    Some(Packet {
        magic,
        timestamp: u64::from_le_bytes(timestamp_bytes),
        channel_id: u32::from_le_bytes(channel_id_bytes),
        data_enc,
        hmac,
        end_magic,
    }) */
    Some(Subscription {
        device_id_bytes,
        channel_bytes,
        start_bytes,
        end_bytes,
        key_data,
    })
}
