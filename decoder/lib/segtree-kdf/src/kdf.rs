use crate::key_hasher::*;
pub use crate::params::*;
use core::array;

#[derive(Clone, Debug)]

pub struct Node {
    pub id: u64,
    pub key: Key,
}

#[cfg(feature = "cache")]
use core::cell::RefCell;
#[cfg(feature = "cache")]
type Cache = [Option<Node>; TREE_HEIGHT + 1];

pub struct SegtreeKDF<H: KeyHasher> {
    pub cover: [[Option<Node>; 2]; TREE_HEIGHT + 1],
    hash: H,

    #[cfg(feature = "cache")]
    cache: RefCell<Cache>,
}

impl<H: KeyHasher> SegtreeKDF<H> {
    pub fn new(cover: [Option<Node>; MAX_COVER_SIZE], last_layer: [Option<Node>; 2]) -> Self {
        let mut constructed_cover: [[Option<Node>; 2]; TREE_HEIGHT + 1] =
            array::from_fn(|_| [None, None]);

        for c in cover {
            if let Some(node) = c {
                let mut bit_count = 0;
                let mut id = node.id;
                while id > 0 {
                    id >>= 1;
                    bit_count += 1;
                }
                let insert_at = if let None = constructed_cover[bit_count - 1][0] {
                    0
                } else if let None = constructed_cover[bit_count - 1][1] {
                    1
                } else {
                    panic!("Too many nodes at level {}", bit_count);
                };
                constructed_cover[bit_count - 1][insert_at] = Some(node);
            }
        }
        constructed_cover[TREE_HEIGHT] = last_layer;

        Self {
            cover: constructed_cover,
            hash: H::new(),
            #[cfg(feature = "cache")]
            cache: RefCell::new(array::from_fn(|_| None)),
        }
    }

    pub fn derive(&self, id: u64) -> Option<Key> {
        for c in &self.cover[TREE_HEIGHT] {
            if let Some(node) = c {
                if node.id == id {
                    return Some(node.key);
                }
            }
        }

        #[cfg(feature = "cache")]
        let cache = self.cache.borrow();

        let mut par = None;
        let mut level = None;
        'outer: for i in 1..(TREE_HEIGHT + 1) {
            let id_trunc = if i == 64 { 0 } else { id >> i };
            let par_id = id_trunc | (1 << (TREE_HEIGHT - i));

            #[cfg(feature = "cache")]
            if let Some(node) = &cache[i] {
                if node.id == par_id {
                    par = Some(node);
                    level = Some(i);
                    break 'outer;
                }
            }

            for c in &self.cover[TREE_HEIGHT - i] {
                if let Some(node) = c {
                    if node.id == par_id {
                        par = Some(node);
                        level = Some(i);
                        break 'outer;
                    }
                }
            }
        }

        let par = par?;
        let level = level?;

        let mut key = par.key.clone();
        let mut cons_id = par.id;

        #[cfg(feature = "cache")]
        drop(cache);
        #[cfg(feature = "cache")]
        let mut cache = self.cache.borrow_mut();

        for i in (TREE_HEIGHT - level)..TREE_HEIGHT {
            let id_bit = id & (1 << (TREE_HEIGHT - i - 1));
            key = self.hash.hash(&key, id_bit != 0);
            cons_id = cons_id << 1 | (if id_bit == 0 { 0 } else { 1 });

            #[cfg(feature = "cache")]
            {
                cache[i] = Some(Node {
                    id: cons_id,
                    key: key.clone(),
                });
            }
        }

        Some(key)
    }
}
