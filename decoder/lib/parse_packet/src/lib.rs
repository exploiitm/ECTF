#![no_std]

#[derive(Debug, Clone)]
pub struct Packet {
    magic: [u8; 8],
    timestamp: u64,
    channel_id: u32,
    data_enc: [u8; 64],
    hmac: [u8; 32],
    end_magic: [u8; 8],
}

fn parse_packet(input: &[u8]) -> Option<Packet> {
    if input.len() != 8 + 8 + 4 + 64 + 32 + 8 {
        return None;
    }

    let mut magic = [0u8; 8];
    let mut timestamp_bytes = [0u8; 8];
    let mut channel_id_bytes = [0u8; 4];
    let mut data_enc = [0u8; 64];
    let mut hmac = [0u8; 32];
    let mut end_magic = [0u8; 8];

    magic.copy_from_slice(&input[0..8]);
    timestamp_bytes.copy_from_slice(&input[8..16]);
    channel_id_bytes.copy_from_slice(&input[16..20]);
    data_enc.copy_from_slice(&input[20..84]);
    hmac.copy_from_slice(&input[84..116]);
    end_magic.copy_from_slice(&input[116..124]);

    Some(Packet {
        magic,
        timestamp: u64::from_le_bytes(timestamp_bytes),
        channel_id: u32::from_le_bytes(channel_id_bytes),
        data_enc,
        hmac,
        end_magic,
    })
}
