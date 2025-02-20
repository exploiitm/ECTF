use crate::params::*;

pub type Key = [u8; KEY_SIZE];

pub trait KeyHasher {
    fn new() -> Self;
    fn hash(&self, data: &Key, direction: bool) -> Key;
}
