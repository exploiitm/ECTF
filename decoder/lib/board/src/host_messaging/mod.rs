const MAGIC: u8 = b'%';
const FRAME_PACKET_SIZE: u8 = 125;
const ACK_PACKET: [u8; 4] = [b'%', b'A', 0x00, 0x00];
pub const SUCCESFUL_SUBSCRIPTION: [u8; 4] = [b'%', b'S', 0x00, 0x00];
const DEBUG_HEADER: [u8; 2] = [b'%', b'G'];
extern crate alloc;
use alloc::{fmt::format, format};
use embedded_io::{Read, Write};

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

use crate::{CHANNEL_ID_SIZE, MAX_NUM_CHANNELS, Subscription, TIMESTAMP_SIZE};

use super::Board;
use alloc::vec;
use alloc::vec::Vec;
use core::{num, ops::Div, panic};

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

// pub fn read_packet(board: &mut Board, length: u16) -> Vec<u8> {
//     if length > 256 {
//         panic!();
//     }

//     let mut data = vec![0; length as usize];
//     for i in 0..(length - 1) {
//         let byte = board.console.read_byte();
//         data[i as usize] = byte;
//     }

//     return data;
// }

pub fn write_decoded_packet(board: &mut Board, data: &[u8]) {
    //IDEALLY SHOULD NOT HAVE TO WRITE MORE THAN 256 BYTES?
    let length = data.len() as u16;
    if length > 256 {
        panic!();
    }
    let header = Header {
        opcode: Opcode::Decode,
        length,
    };
    board.console.write_bytes(&header.as_bytes());
    if read_ack(board) {
        board.console.write_bytes(data);
        if read_ack(board) {
            return;
        } else {
            panic!();
        }
    } else {
        panic!();
    }
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

// #[inline(always)]
// fn _read_packet(board: &mut Board, length: u16) -> Vec<u8> {
//     if length > 256 {
//         panic!();
//     }

//     let mut data = vec![0; length as usize];
//     for i in 0..length {
//         let byte = board.console.read_byte();
//         data[i as usize] = byte;
//     }

//     return data;
// }

pub fn read_frame_packet(board: &mut Board, header: &Header, data: &mut [u8; 125]) {
    if header.length as usize != data.len() {
        panic!();
    }
    board.console.write_bytes(&ACK_PACKET);
    for byte in data {
        *byte = board.console.read_byte();
    }
    board.console.write_bytes(&ACK_PACKET);
}
pub fn subscription_update(board: &mut Board, header: &Header, sub_data: &mut [u8]) {
    board.console.write_bytes(&ACK_PACKET);
    let length = header.length;
    let num_packets: usize = length.div_ceil(256) as usize;

    //getting n-1 packets
    for i in 0..(num_packets - 1) {
        for j in 0..256 {
            let byte = board.console.read_byte();
            sub_data[i * 256 + j] = byte;
        }
        board.console.write_bytes(&ACK_PACKET);
    }

    //getting last packet
    let mut last_packet_size = 0;
    if length % 256 == 0 {
        last_packet_size = 256;
    } else {
        last_packet_size = length % 256;
    }

    for i in 0..(last_packet_size as usize) {
        let byte = board.console.read_byte();
        sub_data[(num_packets - 1) * 256 + i] = byte;
    }
    board.console.write_bytes(&ACK_PACKET);

    send_debug_message(board, "Received subscription data");
}

pub fn succesful_subscription(board: &mut Board) {
    board.console.write_bytes(&SUCCESFUL_SUBSCRIPTION);
    if read_ack(board) {
        return;
    } else {
        panic!();
    }
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
        } else {
            panic!();
        }
    } else {
        panic!();
    }
}
