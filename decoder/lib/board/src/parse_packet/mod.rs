#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: u64,
    pub channel_id: u32,
    pub length: u8,
    pub iv: [u8; 16],
    pub data_enc: [u8; 64],
    pub hmac: [u8; 32],
}

pub fn parse_packet(input: &[u8; 125]) -> Packet {
    let mut timestamp_bytes = [0u8; 8];
    let mut channel_id_bytes = [0u8; 4];
    let length;
    let mut iv = [0u8; 16];
    let mut data_enc = [0u8; 64];
    let mut hmac = [0u8; 32];

    timestamp_bytes.copy_from_slice(&input[0..8]);
    channel_id_bytes.copy_from_slice(&input[8..12]);
    length = input[12];
    iv.copy_from_slice(&input[13..29]);
    data_enc.copy_from_slice(&input[29..93]);
    hmac.copy_from_slice(&input[93..125]);

    Packet {
        timestamp: u64::from_le_bytes(timestamp_bytes),
        channel_id: u32::from_le_bytes(channel_id_bytes),
        length,
        iv,
        data_enc,
        hmac,
    }
}
