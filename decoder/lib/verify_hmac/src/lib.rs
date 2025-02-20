#![no_std]

use hmac::{Hmac, Mac};
use sha3::Sha3_256;

pub use parse_packet::Packet;

/*
fn verify_hmac_better(packet: &Packet, key: &[u8]) -> bool {
    type HMAC = Hmac<Sha256>;
    let mut mac = HMAC::new_from_slice(key);
    let mut hashee = heapless::Vec::<u8, 128>::new();
    hashee.extend_from_slice(&packet.timestamp.to_le_bytes());
}
*/

fn verify_hmac(packet: &Packet, key: &[u8]) -> bool {
    let mut to_hash = heapless::Vec::<u8, 128>::new();

    to_hash
        .extend_from_slice(&packet.timestamp.to_le_bytes())
        .unwrap();
    to_hash
        .extend_from_slice(&packet.channel_id.to_le_bytes())
        .unwrap();
    to_hash.extend_from_slice(&packet.data_enc).unwrap();

    type HmacSha3 = Hmac<Sha3_256>;
    match HmacSha3::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(&to_hash);
            mac.verify_slice(&packet.hmac).is_ok()
        }
        Err(_) => false,
    }
}
