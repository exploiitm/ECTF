use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use cipher::block_padding::NoPadding;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
use hmac::{Hmac, Mac};
use sha3::Sha3_256;
type HmacSha = Hmac<Sha3_256>;
use ed25519_dalek::Signature;
use ed25519_dalek::{Verifier, VerifyingKey};

use crate::Subscription;

const SIGNATURE_BYTES: usize = 64;
const HMAC_BYTES: usize = 32;
const IV_BYTES: usize = 16;

pub fn decrypt_data(data_enc: &[u8; 64], key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8; 64]) {
    let data = Aes256CbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_padded_vec_mut::<NoPadding>(data_enc)
        .expect("Data decryption failed");
    buf.copy_from_slice(&data);
}

pub fn decrypt_sub(
    encrypted_sub: &[u8],
    key: [u8; 32],
    device_id: u32,
    pub_key: &[u8; 32],
) -> Option<Subscription> {
    let signature_received = &encrypted_sub[..SIGNATURE_BYTES];
    let verifying_key =
        VerifyingKey::from_bytes(&pub_key).expect("Verifying key from bytes failed");
    let result = verifying_key.verify(
        &encrypted_sub[SIGNATURE_BYTES..],
        &Signature::try_from(signature_received).unwrap(),
    );
    // board.delay.delay_ms(1);
    if let Err(_) = result {
        panic!("Signature verification failed in decrypt sub");
    }

    let offset = SIGNATURE_BYTES;
    let hmac_received = &encrypted_sub[offset..offset + HMAC_BYTES];

    let mut hmac = HmacSha::new_from_slice(&key).expect("HMac from Sha failed");

    hmac.update(&encrypted_sub[offset + HMAC_BYTES..]);
    let result = hmac.finalize();

    let mut comparison = 0;
    let result = result.into_bytes();

    for byte_tuple in result.iter().zip(hmac_received) {
        comparison |= byte_tuple.0 ^ byte_tuple.1;
    }

    if comparison != 0 {
        panic!("HMAC failure in decrypt sub");
    }

    let offset = offset + HMAC_BYTES;

    let iv = GenericArray::from_slice(&encrypted_sub[offset..offset + IV_BYTES]);
    let ciphertext = &encrypted_sub[offset + IV_BYTES..];

    let k10_new = GenericArray::from_slice(&key);
    let decryptor = Aes256CbcDec::new(k10_new, iv);

    let decrypted_data = decryptor
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .expect("Data decryption failed in decrypt sub");

    let length_bytes: [u8; 8] = decrypted_data[0..8].try_into().unwrap();
    let device_id_bytes: [u8; 4] = decrypted_data[8..12].try_into().unwrap();
    let channel_bytes: [u8; 4] = decrypted_data[12..16].try_into().unwrap();
    let start_bytes: [u8; 8] = decrypted_data[16..24].try_into().unwrap();
    let end_bytes: [u8; 8] = decrypted_data[24..32].try_into().unwrap();

    let key_data = &decrypted_data[32..u64::from_le_bytes(length_bytes) as usize + 8];
    let device_id_received = u32::from_le_bytes(device_id_bytes);
    let channel = u32::from_le_bytes(channel_bytes);
    let start = u64::from_le_bytes(start_bytes);
    let end = u64::from_le_bytes(end_bytes);
    if device_id != device_id_received {
        None
    } else {
        let subscription = Subscription::new(channel, start, end, key_data);
        Some(subscription)
    }
}
