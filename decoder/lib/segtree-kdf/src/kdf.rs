use crate::key_hasher::*;
pub use crate::params::*;
use core::array;

#[derive(Clone, Debug)]

pub struct Node {
    pub id: u64,
    pub key: Key,
}

// type Cache = [Option<Node>; TREE_HEIGHT + 1];

pub struct SegtreeKDF<H: KeyHasher> {
    pub cover: [[Option<Node>; 2]; TREE_HEIGHT + 1],
    hash: H,
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
                let insert_at = if let Some(_) = constructed_cover[bit_count][0] {
                    1
                } else {
                    0
                };
                constructed_cover[bit_count - 1][insert_at] = Some(node);
            }
        }
        constructed_cover[TREE_HEIGHT] = last_layer;

        Self {
            cover: constructed_cover,
            hash: H::new(),
        }
    }

    fn try_derive(&self, id: u64, level: usize /* , cache: &mut Cache */) -> Option<Key> {
        for c in &self.cover[level] {
            if let Some(node) = c {
                if node.id == id {
                    return Some(node.key.clone());
                }
            }
        }

        if level == 0 {
            return None;
        }

        let par_key = self.try_derive(id >> 1, level - 1 /* , cache */)?;
        let node = Node {
            id,
            key: self.hash.hash(&par_key, id & 1 == 1),
        };
        // cache[level] = Some(node.clone());
        Some(node.key)
    }

    pub fn derive(&self, id: u64) -> Option<Key> {
        for c in &self.cover[TREE_HEIGHT] {
            if let Some(node) = c {
                if node.id == id {
                    return Some(node.key);
                }
            }
        }

        let par_id = (id >> 1) | (1 << 63);
        let par = self.try_derive(par_id, TREE_HEIGHT - 1)?;
        let node = Node {
            id,
            key: self.hash.hash(&par, id & 1 == 1),
        };
        // cache[TREE_HEIGHT] = Some(node.clone());
        Some(node.key)
    }
}
