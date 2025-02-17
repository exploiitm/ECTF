const MAGIC: u8 = b'%';
const ACK_PACKET: [u8; 4]  = [b'%', b'A', 0x00, 0x00];
const DEBUG_HEADER: [u8; 2] = [b'%', b'G']; 
extern crate alloc;
use alloc::{fmt::format, format};
use embedded_io::Write;
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

use crate::Subscription;

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
    } else {
        panic!();
    }
}

// pub fn decode(board: &mut Board, header: Header) {
//     board.console.write_bytes(&ACK_PACKET);
//     let length = header.length;
//     let num_packets: u16 = length / 256;

//     for _ in 0..num_packets {
//         let packet = read_packet(board, 256);
//         board.console.write_bytes(&ACK_PACKET);
//         //TODO :: DO WHAT YOU WILL WITH THESE PACKETS
//     }
//     if length % 256 != 0 {
//         let packet = read_packet(board, length % 256);
//         board.console.write_bytes(&ACK_PACKET);
//         //TODO :: DO WHAT YOU WILL DO WITH THESE PACKETS
//     }
//     //TODO call write_decoded_packet after decoding the packets.
// }
#[inline(always)]
fn _send_debug_message(board: &mut Board, message: &str) {
    let length = message.len() as u16;
    let header = Header {
        opcode: Opcode::Debug,
        length,
    };
    board.console.write_bytes(&header.as_bytes());
    board.console.write_bytes(message.as_bytes());
}

#[inline(always)]
fn _read_packet(board: &mut Board, length: u16) -> Vec<u8> {
    if length > 256 {
        panic!();
    }

    let mut data = vec![0; length as usize];
    for i in 0..(length - 1) {
        let byte = board.console.read_byte();
        data[i as usize] = byte;
    }

    return data;
}

pub fn subscription_update(board: &mut Board, header: Header) -> vec::Vec<u8> {
    board.console.write_bytes(&ACK_PACKET);
    let length = header.length;

    let mut sub_data = vec![0u8; length as usize];

    // _send_debug_message(board, format!("Length: {}", length).as_str());

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
    let packet = _read_packet(board, length % 256);
    for i in 0..(length as usize % 256) {
        sub_data[(num_packets - 1) * 256 + i] = packet[i];
    } 
    board.console.write_bytes(&ACK_PACKET);

    _send_debug_message(board, format!("Read all packets").as_str());

    let message = format!("first few bytes of subscripion data: {}", &sub_data[40]);
    _send_debug_message(board, message.as_str());

    sub_data
}

// pub fn subscription_update(board: &mut Board, header: Header) -> Subscription {
//     board.console.write_bytes(&ACK_PACKET);

//     let length = header.length;
//     let mut sub_data = vec![0; length as usize];

//     board.console.write_bytes(&DEBUG_HEADER);
//     let message = b"Reading Subscription Data";
//     let length_bytes = (message.len() as u16).to_le_bytes();
//     board.console.write_bytes(&length_bytes);
//     board.console.write_bytes(message);

//     let num_packets: usize = (length / 256) as usize;

//     board.console.write_bytes(&DEBUG_HEADER);
//     let message = format!("Number of packets: {}", num_packets);
//     let length_bytes = (message.len() as u16).to_le_bytes();
//     board.console.write_bytes(&length_bytes);
//     board.console.write_bytes(message.as_bytes());

//     for i in 0..num_packets {
//         let packet = read_packet(board, 256);
//         board.console.write_bytes(&ACK_PACKET);
//         sub_data[i * 256..(i + 1) * 256].copy_from_slice(&packet);
//     }

//     if length % 256 != 0 {
//         let packet = read_packet(board, length % 256);
//         sub_data[num_packets * 256..].copy_from_slice(&packet);
//         board.console.write_bytes(&ACK_PACKET);
//     }

//     parse_subscriptions(&sub_data)
// }

pub fn parse_subscriptions(_packed_sub: &[u8]) -> Subscription {
    //TODO:: parse all the packets
    todo!();
}

pub fn list_subscriptions(board: &mut Board) {
    board.console.write_bytes(&ACK_PACKET);
    //TODO :: implement how to get this msg
    let msg: &[u8] = &[
        0x02, 0x00, 0x00, 0x00, // Number of channels (2)
        0x01, 0x00, 0x00, 0x00, // 1st channel ID (1)
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Start timestamp (128)
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // End timestamp (255)
        0x04, 0x00, 0x00, 0x00, // 1st channel ID (4)
        0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Start timestamp (0x4141)
        0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // End timestamp (0x4242)
    ];

    let list_header = Header {
        opcode: Opcode::List,
        length: msg.len() as u16,
    };
    board.console.write_bytes(&list_header.as_bytes());
    if read_ack(board) {
        board.console.write_bytes(msg);
    } else {
        panic!();
    }
}
