extern crate alloc;
use core::panic;

use super::Board;
use crate::{CHANNEL_ID_SIZE, MAX_NUM_CHANNELS, TIMESTAMP_SIZE, parse_packet::FRAME_PACKET_SIZE};

pub const MAGIC: u8 = b'%';
pub const ACK_PACKET: [u8; 4] = [b'%', b'A', 0x00, 0x00];
pub const SUCCESFUL_SUBSCRIPTION: [u8; 4] = [b'%', b'S', 0x00, 0x00];
pub const DEBUG_HEADER: [u8; 2] = [b'%', b'G'];
pub const ERROR_MSG: [u8; 4] = [b'%', b'E', 0x00, 0x00];
pub const ACK_LENGTH: usize = 256;

pub enum Opcode {
    Decode,
    Subscribe,
    List,
    Ack,
    Error,
    Debug,
}

impl Opcode {
    pub fn as_byte(&self) -> u8 {
        match self {
            Opcode::Decode => b'D',
            Opcode::Subscribe => b'S',
            Opcode::List => b'L',
            Opcode::Ack => b'A',
            Opcode::Error => b'E',
            Opcode::Debug => b'G',
        }
    }
}

pub struct Header {
    pub opcode: Opcode,
    pub length: u16,
}

impl Header {
    pub fn as_bytes(&self) -> [u8; 4] {
        let opcode = self.opcode.as_byte();
        let length = self.length.to_le_bytes();
        [MAGIC, opcode, length[0], length[1]]
    }
}

pub fn read_header(board: &mut Board) -> Header {
    let mut byte = board.console.read_byte();
    while byte != MAGIC {
        byte = board.console.read_byte();
    }
    let opcode_byte = board.console.read_byte();
    let mut length: [u8; 2] = [0; 2];
    board.console.read_bytes(&mut length);
    let opcode = match opcode_byte {
        b'D' => Opcode::Decode,
        b'S' => Opcode::Subscribe,
        b'L' => Opcode::List,
        b'A' => Opcode::Ack,
        b'E' => Opcode::Error,
        b'G' => Opcode::Debug,
        _ => panic!("Invalid opcode"),
    };

    let length = u16::from_le_bytes(length);

    return Header { opcode, length };
}
pub fn read_ack(board: &mut Board) -> bool {
    let ack_header = read_header(board);
    match ack_header.opcode {
        Opcode::Ack => {
            return true;
        }
        _ => {
            return false;
        }
    }
}

pub fn write_decoded_packet(board: &mut Board, data: &[u8]) {
    let length = data.len();
    if length > ACK_LENGTH {
        panic!("Ack length panic cup");
    }
    let header = Header {
        opcode: Opcode::Decode,
        length: length as u16,
    };
    board.console.write_bytes(&header.as_bytes());
    if read_ack(board) {
        board.console.write_bytes(data);
        if read_ack(board) {
            return;
        }
    }
    panic!("write decoded packet panic cup");
}

pub fn send_debug_message(board: &mut Board, message: &str) {
    let length = message.len() as u16;
    let header = Header {
        opcode: Opcode::Debug,
        length,
    };
    board.console.write_bytes(&header.as_bytes());
    board.console.write_bytes(message.as_bytes());
}

pub fn send_error_message(board: &mut Board, message: &str) {
    let length = message.len() as u16;

    // BRo you dont need that much length.
    if length > 256 {
        panic!("Message too large");
    }

    let header = Header {
        opcode: Opcode::Error,
        length,
    };
    board.console.write_bytes(&header.as_bytes());
    if read_ack(board) {
        board.console.write_bytes(message.as_bytes());
        if read_ack(board) {
            return;
        }
    }
}

pub fn read_frame_packet(board: &mut Board, header: &Header, data: &mut [u8; FRAME_PACKET_SIZE]) {
    if header.length as usize != data.len() {
        panic!("Read frame packet header length cup");
    }
    board.console.write_bytes(&ACK_PACKET);
    for byte in data {
        *byte = board.console.read_byte();
    }
    send_debug_message(board, "gonna send final ack inside read_frame_packet");
    board.console.write_bytes(&ACK_PACKET);
}
pub fn subscription_update(board: &mut Board, header: &Header, sub_data: &mut [u8]) {
    board.console.write_bytes(&ACK_PACKET);
    let length = header.length;
    let num_packets: usize = length.div_ceil(256) as usize;

    //getting n-1 packets
    for i in 0..(num_packets - 1) {
        for j in 0..ACK_LENGTH {
            let byte = board.console.read_byte();
            sub_data[i * ACK_LENGTH + j] = byte;
        }
        board.console.write_bytes(&ACK_PACKET);
    }

    //getting last packet
    let last_packet_size = if length as usize % ACK_LENGTH == 0 {
        ACK_LENGTH
    } else {
        length as usize % ACK_LENGTH
    };

    for i in 0..(last_packet_size as usize) {
        let byte = board.console.read_byte();
        sub_data[(num_packets - 1) * ACK_LENGTH + i] = byte;
    }
    board.console.write_bytes(&ACK_PACKET);
}

pub fn succesful_subscription(board: &mut Board) {
    board.console.write_bytes(&SUCCESFUL_SUBSCRIPTION);
    if read_ack(board) {
        return;
    }
    panic!("successful subscription panic cup");
}

pub fn list_subscriptions(board: &mut Board) {
    board.console.write_bytes(&ACK_PACKET);

    let mut msg = [0u8; 4 + (2 * TIMESTAMP_SIZE + CHANNEL_ID_SIZE) * MAX_NUM_CHANNELS];

    let length = board.subscriptions.list_subscriptions(&mut msg);
    let list_header = Header {
        opcode: Opcode::List,
        length: length as u16,
    };
    board.console.write_bytes(&list_header.as_bytes());

    if read_ack(board) {
        board.console.write_bytes(&msg);
        if read_ack(board) {
            return;
        }
    }
    panic!("List subscription panic cup");
}
