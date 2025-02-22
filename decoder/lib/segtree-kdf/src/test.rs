use crate::{params::*, *};
use core::array;

struct DummyHasher();

impl KeyHasher for DummyHasher {
    fn new() -> Self {
        DummyHasher()
    }

    fn hash(&self, key: &Key, direction: bool) -> Key {
        let mut new_key = key.clone();
        for byte in 0..KEY_SIZE {
            if direction {
                if new_key[byte] == 255 {
                    new_key[byte] = 0;
                } else {
                    new_key[byte] = key[byte] + 1;
                    break;
                }
            } else {
                if new_key[byte] == 0 {
                    new_key[byte] = 255;
                } else {
                    new_key[byte] = key[byte] - 1;
                    break;
                }
            }
        }

        new_key
    }
}

// #[test]
// fn dummy_hash_left() {
//     let zero = [0; KEY_SIZE];
//     let h = DummyHasher::new();
//     assert_eq!(h.hash(&zero, false), [255; KEY_SIZE]);
// }
//
// #[test]
// fn dummy_hash_right() {
//     let ff = [255; KEY_SIZE];
//     let h = DummyHasher::new();
//     assert_eq!(h.hash(&ff, true), [0; KEY_SIZE]);
// }

#[test]
fn derives_right_from_zero() {
    let mut cover: [Option<Node>; MAX_COVER_SIZE] = array::from_fn(|_| None);
    cover[0] = Some(Node {
        id: 1,
        key: [0; KEY_SIZE],
    });
    let last_layer = [None, None];
    let kdf = SegtreeKDF::<DummyHasher>::new(&cover, &last_layer);

    let mut key = [0; KEY_SIZE];
    key[0] = 64;
    assert_eq!(kdf.derive(0xFFFF_FFFF_FFFF_FFFF), Some(key));
}

#[test]
fn derives_alternating_from_zero() {
    let mut cover: [Option<Node>; MAX_COVER_SIZE] = array::from_fn(|_| None);
    cover[0] = Some(Node {
        id: 1,
        key: [0; KEY_SIZE],
    });
    let last_layer = [None, None];
    let kdf = SegtreeKDF::<DummyHasher>::new(&cover, &last_layer);

    let key = [0; KEY_SIZE];
    assert_eq!(kdf.derive(0x5555_5555_5555_5555), Some(key));
}

#[test]
fn accepts_leaf() {
    let cover: [Option<Node>; MAX_COVER_SIZE] = array::from_fn(|_| None);
    let last_layer = [
        Some(Node {
            id: 5,
            key: [5; KEY_SIZE],
        }),
        None,
    ];

    let kdf = SegtreeKDF::<DummyHasher>::new(&cover, &last_layer);
    let key = [5; KEY_SIZE];
    assert_eq!(kdf.derive(5), Some(key));
}

#[test]
fn accepts_node() {
    let mut cover: [Option<Node>; MAX_COVER_SIZE] = array::from_fn(|_| None);
    cover[0] = Some(Node {
        id: 0x12345,
        key: [5; KEY_SIZE],
    });
    let last_layer = [None, None];

    let kdf = SegtreeKDF::<DummyHasher>::new(&cover, &last_layer);
    let key = [5; KEY_SIZE];
    assert_eq!(kdf.derive(0x2345_AAAA_AAAA_AAAA), Some(key));
}
