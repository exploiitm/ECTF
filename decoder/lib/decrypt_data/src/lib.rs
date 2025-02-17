#![no_std]
use cipher::consts::U16;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn decrypt_data(data_enc: &[u8; 64], key: &[u8; 32], iv: &[u8; 16]) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf.copy_from_slice(data_enc);
    let mut gen_arr = [
        *GenericArray::<u8, U16>::from_mut_slice(&mut buf[0..16]),
        *GenericArray::<u8, U16>::from_mut_slice(&mut buf[16..32]),
        *GenericArray::<u8, U16>::from_mut_slice(&mut buf[32..48]),
        *GenericArray::<u8, U16>::from_mut_slice(&mut buf[48..64]),
    ];
    Aes128CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_blocks_mut(&mut gen_arr);

    buf
}
