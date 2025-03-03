#![no_std]

extern crate alloc;
use alloc::collections::BTreeMap;
use core::array;
use host_messaging::DEBUG_HEADER;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use max7800x_hal::{
    self as hal,
    gpio::{Af1, InputOutput},
    pac::{self, Peripherals, Uart0},
    uart::BuiltUartPeripheral,
};
use segtree_kdf::{self, KEY_SIZE, Key, KeyHasher};

pub mod parse_packet;

pub const CHANNEL_ID_SIZE: usize = 4;
pub const TIMESTAMP_SIZE: usize = 8;
pub const MAX_NUM_CHANNELS: usize = 8;
pub const KEY_LENGTH: usize = KEY_SIZE;
pub const NODE_SIZE: usize = 8;

pub const LOOKUP_TABLE_LOCATION: u32 = 0x10032000;
pub const CHANNEL_PAGE_START: u32 = 0x10034000;
pub const SAFETY_LOCATION: u32 = 0x10030f88;
pub const SAFETY_PAGE: u32 = 0x10030000;
pub const PAGE_SIZE: u32 = 8192;
pub const MAX_SUBSCRIPTION_SIZE: usize = 5160;

//Led Pins Struct
struct LedPins {
    led_r: hal::gpio::Pin<2, 0, InputOutput>,
}

pub struct Board {
    pub delay: cortex_m::delay::Delay,
    pub console:
        BuiltUartPeripheral<Uart0, hal::gpio::Pin<0, 0, Af1>, hal::gpio::Pin<0, 1, Af1>, (), ()>, // flc: hal::flc::Flc,
    pub flc: hal::flc::Flc,
    led_pins: LedPins,
    pub subscriptions: Subscriptions,
    pub trng: hal::trng::Trng,
}

pub struct SHA256HasherTrunc128 {
    pub key_left: [u8; 32],
    pub key_right: [u8; 32],
}

impl KeyHasher for SHA256HasherTrunc128 {
    fn new() -> Self {
        let key_left_base: u32 = 0xDEADBEEF;
        let key_left = key_left_base
            .to_le_bytes()
            .repeat(8)
            .try_into()
            .expect("Left key into array failed in KeyHasher::new");
        let key_right_base: u32 = 0xC0D3D00D;
        let key_right = key_right_base
            .to_le_bytes()
            .repeat(8)
            .try_into()
            .expect("Right key into array failed in KeyHasher::new");

        SHA256HasherTrunc128 {
            key_left,
            key_right,
        }
    }

    fn hash(&self, data: &Key, direction: bool) -> Key {
        let key = match direction {
            true => self.key_left,
            false => self.key_right,
        };

        let mut mac = Sha3_256::new();
        mac.update(&key);
        mac.update(data);

        let slice = mac.finalize().as_slice()[..KEY_SIZE]
            .try_into()
            .expect("mac finalization failed");
        return slice;
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChannelFlashMap {
    pub map: BTreeMap<u32, u32>, // Maps the channel ID to the flash page
}

impl ChannelFlashMap {
    pub fn rebuild_from_flash(board: &mut Board) -> Self {
        // Reconstruction of the channel map from flash
        board.read_channel_map().unwrap_or(ChannelFlashMap {
            map: BTreeMap::new(),
        })
    }
}

pub struct Subscription {
    pub channel: u32,
    pub start: u64,
    pub end: u64,
    pub kdf: segtree_kdf::SegtreeKDF<SHA256HasherTrunc128>,
}

pub struct Subscriptions {
    pub size: u8,
    pub subscriptions: [Option<Subscription>; MAX_NUM_CHANNELS],
}

impl Subscription {
    pub fn new(channel: u32, start: u64, end: u64, keys: &[u8]) -> Self {
        let num_nodes_bytes = keys[0..NODE_SIZE]
            .try_into()
            .expect("keys.try_into failed in Subscription::new");
        let num_nodes = u64::from_le_bytes(num_nodes_bytes) as usize;
        let keys = &keys[NODE_SIZE..];

        let mut cover: [Option<segtree_kdf::Node>; segtree_kdf::MAX_COVER_SIZE] =
            array::from_fn(|_| None);

        for i in 0..num_nodes {
            let id_bytes = keys[i * (KEY_LENGTH + TIMESTAMP_SIZE)
                ..i * (KEY_LENGTH + TIMESTAMP_SIZE) + TIMESTAMP_SIZE]
                .try_into()
                .expect("id_bytes from keys failed for a particular iteration");
            let id = u64::from_le_bytes(id_bytes);
            let key_bytes = &keys[i * (KEY_LENGTH + TIMESTAMP_SIZE) + TIMESTAMP_SIZE
                ..(i + 1) * (KEY_LENGTH + TIMESTAMP_SIZE)];
            let node = segtree_kdf::Node {
                id,
                key: key_bytes
                    .try_into()
                    .expect("Key bytes to key failed in a particular iteration"),
            };
            cover[i] = Some(node);
        }

        let mut last_layer: [Option<segtree_kdf::Node>; 2] = array::from_fn(|_| None);
        let num_leaves = keys.len() / (KEY_LENGTH + TIMESTAMP_SIZE) - num_nodes;

        for i in 0..num_leaves {
            let id_bytes = keys[(num_nodes + i) * (KEY_LENGTH + TIMESTAMP_SIZE)
                ..(num_nodes + i) * (KEY_LENGTH + TIMESTAMP_SIZE) + TIMESTAMP_SIZE]
                .try_into()
                .expect("Leaf ID died");
            let id = u64::from_le_bytes(id_bytes);
            let key_bytes = keys[(num_nodes + i) * (KEY_LENGTH + TIMESTAMP_SIZE) + TIMESTAMP_SIZE
                ..(num_nodes + i + 1) * (KEY_LENGTH + TIMESTAMP_SIZE)]
                .try_into()
                .expect("Leaf key died");
            let node = segtree_kdf::Node { id, key: key_bytes };
            last_layer[i] = Some(node);
        }
        let kdf = segtree_kdf::SegtreeKDF::new(cover, last_layer);

        Subscription {
            channel,
            start,
            end,
            kdf,
        }
    }
}

impl Subscriptions {
    pub fn new() -> Self {
        Subscriptions {
            size: 0,
            subscriptions: array::from_fn(|_| None),
        }
    }
    pub fn add_subscription(&mut self, sub: Subscription) -> bool {
        for i in 0..MAX_NUM_CHANNELS {
            match &self.subscriptions[i] {
                Some(subscription) => {
                    if subscription.channel == sub.channel {
                        self.subscriptions[i] = Some(sub);
                        return false;
                    }
                }
                None => {
                    self.subscriptions[i] = Some(sub);
                    self.size += 1;
                    return true;
                }
            }
        }
        panic!("No subscription space, more than 8 sent");
    }

    pub fn list_subscriptions(&self, message: &mut [u8]) -> u8 {
        let num_channels = self.size as u32;
        let num_channels_bytes = num_channels.to_le_bytes();
        message[0..num_channels_bytes.len()].copy_from_slice(&num_channels_bytes);
        let mut length = num_channels_bytes.len();
        for sub in &self.subscriptions[0..num_channels as usize] {
            if let Some(sub) = sub {
                let channel_id_bytes = sub.channel.to_le_bytes();
                message[length..(length + CHANNEL_ID_SIZE)].copy_from_slice(&channel_id_bytes);
                length += CHANNEL_ID_SIZE;
                let start_bytes = sub.start.to_le_bytes();
                message[length..(length + TIMESTAMP_SIZE)].copy_from_slice(&start_bytes);
                length += TIMESTAMP_SIZE;
                let end_bytes = sub.end.to_le_bytes();
                message[length..(length + TIMESTAMP_SIZE)].copy_from_slice(&end_bytes);
                length += TIMESTAMP_SIZE;
            }
        }
        length as u8
    }
}

use core::panic::PanicInfo;

pub mod decrypt_data;
pub mod host_messaging;
unsafe impl Sync for Board {}

impl Board {
    pub fn new() -> Self {
        //Take ownership of the MAX78000 peripherals
        let peripherals: Peripherals = Peripherals::take().unwrap();
        let core = pac::CorePeripherals::take().unwrap();

        //constrain the Global Control Register (GCR) Peripheral
        let mut gcr = hal::gcr::Gcr::new(peripherals.gcr, peripherals.lpgcr);

        //Initialize the Internap Primary Oscillator (IPO)
        let ipo = hal::gcr::clocks::Ipo::new(gcr.osc_guards.ipo).enable(&mut gcr.reg);
        let clks = gcr.sys_clk.set_source(&mut gcr.reg, &ipo).freeze();
        let delay = cortex_m::delay::Delay::new(core.SYST, clks.sys_clk.frequency);
        let pins = hal::gpio::Gpio2::new(peripherals.gpio2, &mut gcr.reg).split();
        let gpio0_pins = hal::gpio::Gpio0::new(peripherals.gpio0, &mut gcr.reg).split();

        // Configure UART to host computer with 115200 8N1 settings
        let rx_pin = gpio0_pins.p0_0.into_af1();
        let tx_pin = gpio0_pins.p0_1.into_af1();

        //initializing the console
        let console =
            hal::uart::UartPeripheral::uart0(peripherals.uart0, &mut gcr.reg, rx_pin, tx_pin)
                .baud(115200)
                .clock_pclk(&clks.pclk)
                .parity(hal::uart::ParityBit::None)
                .build();

        let trng = hal::trng::Trng::new(peripherals.trng, &mut gcr.reg);

        let flc = hal::flc::Flc::new(peripherals.flc, clks.sys_clk);
        console.write_bytes(b"Flash Initialized\r\n");
        Board {
            delay,
            console,
            flc,
            led_pins: LedPins {
                led_r: {
                    let led_r = pins.p2_0.into_input_output();
                    led_r
                },
            },
            subscriptions: Subscriptions::new(),
            trng,
        }
    }

    pub fn set_safety_bit(&mut self) -> Result<u32, hal::flc::FlashError> {
        let addr = SAFETY_LOCATION;
        let new_value = 0xffffffff;
        self.flc.write_32(addr, new_value)?;
        Ok(new_value)
    }
    pub fn reset_safety_bit(&mut self) -> Result<u32, hal::flc::FlashError> {
        let addr = SAFETY_LOCATION;
        let new_value = 0;
        self.flc.write_32(addr, new_value)?;
        Ok(new_value)
    }

    pub fn is_safety_bit_set(&mut self) -> bool {
        let last_32bit_addr = SAFETY_LOCATION;
        let current_value = self
            .flc
            .read_32(last_32bit_addr)
            .expect("Weren't able to read safety bit. welp");
        (current_value & 0xFF) as u8 > 0
    }

    // Write subscription data to flash
    pub fn write_sub_to_flash(
        &mut self,
        address: u32,
        data: &[u8],
    ) -> Result<(), hal::flc::FlashError> {
        let data_length = data.len() as u32; // Get the length of data
        let max_size = MAX_SUBSCRIPTION_SIZE; // Maximum size of a subscription

        if data_length > max_size as u32 {
            return Err(hal::flc::FlashError::NeedsErase);
        }

        unsafe {
            self.flc.erase_page(address)?;
        }

        self.flc.write_32(address, data_length)?;

        let mut write_addr = address + 4;

        // Write actual data in 16-byte aligned chunks
        for chunk in data.chunks(16) {
            let mut padded_chunk = [0xFFu8; 16]; // Default erased flash value for bytes
            padded_chunk[..chunk.len()].copy_from_slice(chunk);

            for (offset, word_bytes) in padded_chunk.chunks(4).enumerate() {
                let word = u32::from_le_bytes(
                    word_bytes
                        .try_into()
                        .expect("word from 4 bytes in writing failed"),
                );
                self.flc.write_32(write_addr + (offset as u32 * 4), word)?;
            }

            write_addr += 16;
        }

        Ok(())
    }

    // Read one subscription from flash
    pub fn read_sub_from_flash(
        &mut self,
        address: u32,
        buffer: &mut [u8; MAX_SUBSCRIPTION_SIZE],
    ) -> Result<u32, hal::flc::FlashError> {
        // Read the stored subscription size (first 4 bytes)
        let subscription_size = self.flc.read_32(address)?;
        if subscription_size == 0xFFFFFFFF || subscription_size > MAX_SUBSCRIPTION_SIZE as u32 {
            return Err(hal::flc::FlashError::InvalidAddress);
        }

        let mut read_addr = address + 4;
        // Read exactly `subscription_size` bytes into the buffer
        for chunk_index in 0..(subscription_size as usize / 16 + 1) {
            let chunk_start = chunk_index * 16;
            let chunk_end = (chunk_start + 16).min(subscription_size as usize);
            let mut chunk = [0u8; 16];

            for (j, word_addr) in (0..4).map(|offset| read_addr + (offset * 4)).enumerate() {
                let word = self.flc.read_32(word_addr)?;
                chunk[j * 4..(j + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }

            read_addr += 16;
            buffer[chunk_start..chunk_end].copy_from_slice(&chunk[..chunk_end - chunk_start]);
        }

        buffer[subscription_size as usize..].fill(0);

        Ok(subscription_size)
    }

    // Reads the channel mapping from the flash for reconstruction
    pub fn read_channel_map(&mut self) -> Result<ChannelFlashMap, hal::flc::FlashError> {
        let dict_addr = LOOKUP_TABLE_LOCATION; // Dictionary stored at this address

        let data_size = self.flc.read_32(dict_addr)? as usize;

        if data_size == 0xFFFFFFFF || data_size == 0 || data_size > PAGE_SIZE as usize {
            return Ok(ChannelFlashMap {
                map: BTreeMap::new(),
            });
        }

        let mut read_addr = dict_addr + 4;
        let mut serialized_data = alloc::vec::Vec::new();

        for _ in 0..(data_size / 16 + 1) {
            let mut chunk = [0u8; 16];

            for (j, word_addr) in (0..4).map(|offset| read_addr + (offset * 4)).enumerate() {
                let word = self.flc.read_32(word_addr)?;
                chunk[j * 4..(j + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }

            read_addr += 16;
            serialized_data.extend_from_slice(&chunk);
        }

        postcard::from_bytes(&serialized_data).or(Ok(ChannelFlashMap {
            map: BTreeMap::new(),
        }))
    }

    // Writes the channel mapping to the flash
    pub fn write_channel_map(
        &mut self,
        channel_map: &ChannelFlashMap,
    ) -> Result<(), hal::flc::FlashError> {
        let dict_addr = LOOKUP_TABLE_LOCATION; // TODO:finalise the page/location in the memory
        let page_size = PAGE_SIZE;

        let serialized_data =
            postcard::to_allocvec(channel_map).map_err(|_| hal::flc::FlashError::InvalidAddress)?;

        let data_len = serialized_data.len() as u32;

        if (data_len + 4) > (page_size as usize).try_into().unwrap() {
            return Err(hal::flc::FlashError::NeedsErase);
        }

        unsafe {
            self.flc.erase_page(dict_addr)?;
        }

        self.flc.write_32(dict_addr, data_len)?;

        let dict_addr_new = dict_addr + 4; // Moved past the size of the data
        for (i, chunk) in serialized_data.chunks(16).enumerate() {
            let addr = dict_addr_new + (i * 16) as u32;
            let mut padded_chunk = [0xFFu8; 16];
            padded_chunk[..chunk.len()].copy_from_slice(chunk);

            for (offset, word_bytes) in padded_chunk.chunks(4).enumerate() {
                let word = u32::from_le_bytes(
                    word_bytes
                        .try_into()
                        .expect("serialization failed in writing channel map"),
                );
                self.flc.write_32(addr + (offset as u32 * 4), word)?;
            }
        }

        Ok(())
    }

    // Finds and available page for the subscription
    pub fn find_available_page(
        &mut self,
        channel_map: &ChannelFlashMap,
    ) -> Result<u32, hal::flc::FlashError> {
        let start_addr = CHANNEL_PAGE_START;
        let page_size = PAGE_SIZE;
        let num_pages = 10;

        for i in 0..num_pages {
            let page_addr = start_addr + (i * page_size);

            if !channel_map.map.values().any(|addr| *addr == page_addr) {
                return Ok(page_addr);
            }
        }

        Err(hal::flc::FlashError::InvalidAddress) // No available pages
    }

    // Assign a page for the subscription and erase existing one if so
    pub fn assign_page_for_subscription(
        &mut self,
        channel_map: &mut ChannelFlashMap,
        channel_id: u32,
        new_page: u32,
    ) -> Result<(), hal::flc::FlashError> {
        channel_map.map.insert(channel_id, new_page);
        self.write_channel_map(channel_map)?;

        Ok(())
    }
    pub fn lockdown(&mut self) {
        self.delay.delay_ms(3000);
        let addr = SAFETY_PAGE;
        unsafe {
            self.flc
                .erase_page(addr)
                .expect("Weren't able to erase page")
        };

        self.led_pins.led_r.set_high();
        self.delay.delay_ms(3000);
        self.led_pins.led_r.set_low();
        self.delay.delay_ms(3000);
    }

    pub fn gen_u32_trng(&mut self) -> u32 {
        self.trng.gen_u32()
    }

    pub fn random_delay(&mut self, outer_max: u32, inner_max: u32) {
        let mut out_val = 0;
        let out_ptr: *mut u32 = &mut out_val;
        let outer_val = self.gen_u32_trng() % outer_max;
        let inner_val = self.gen_u32_trng() % inner_max;
        for i in 0..outer_val {
            for j in 0..inner_val {
                let val = out_val.wrapping_mul(i).wrapping_add(69);
                let val = val.wrapping_mul(420).wrapping_sub(j);
                unsafe {
                    core::ptr::write_volatile(out_ptr, val);
                }
            }
        }
    }
}

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    let peripherals: Peripherals = unsafe { Peripherals::steal() };
    let core: pac::CorePeripherals = unsafe { pac::CorePeripherals::steal() };

    let mut gcr = hal::gcr::Gcr::new(peripherals.gcr, peripherals.lpgcr);
    //Initialize the Internap Primary Oscillator (IPO)
    let ipo = hal::gcr::clocks::Ipo::new(gcr.osc_guards.ipo).enable(&mut gcr.reg);
    let clks = gcr.sys_clk.set_source(&mut gcr.reg, &ipo).freeze();
    let mut delay = cortex_m::delay::Delay::new(core.SYST, clks.sys_clk.frequency);
    let pins = hal::gpio::Gpio2::new(peripherals.gpio2, &mut gcr.reg).split();

    let mut led_r = pins.p2_0.into_input_output();
    let mut led_g = pins.p2_1.into_input_output();
    let mut led_b = pins.p2_2.into_input_output();
    led_r.set_power_vddioh();
    led_g.set_power_vddioh();
    led_b.set_power_vddioh();

    let gpio0_pins = hal::gpio::Gpio0::new(peripherals.gpio0, &mut gcr.reg).split();
    // Configure UART to host computer with 115200 8N1 settings
    let rx_pin = gpio0_pins.p0_0.into_af1();
    let tx_pin = gpio0_pins.p0_1.into_af1();

    let flc = hal::flc::Flc::new(peripherals.flc, clks.sys_clk);

    //initializing the console
    let console = hal::uart::UartPeripheral::uart0(peripherals.uart0, &mut gcr.reg, rx_pin, tx_pin)
        .baud(115200)
        .clock_pclk(&clks.pclk)
        .parity(hal::uart::ParityBit::None)
        .build();

    let debug_header = DEBUG_HEADER;
    console.write_bytes(&debug_header);
    delay.delay_ms(1000);
    let message = info.message();

    let message = message.as_str().unwrap_or("Unknown panic");
    let message_len_bytes = message.len().to_le_bytes();
    console.write_bytes(&message_len_bytes);
    console.write_bytes(message.as_bytes());
    console.flush_tx();

    console.write_bytes(b"Bit reset :)\r\n");
    console.flush_tx();

    // Erasing the lookup table and the stored subscriptions
    unsafe {
        flc.erase_page(LOOKUP_TABLE_LOCATION).unwrap();
    }
    let start_addr = CHANNEL_PAGE_START;
    for i in 1..10 {
        let current_addr = start_addr + (i * PAGE_SIZE);

        unsafe {
            flc.erase_page(current_addr).unwrap();
        }
    }

    // Resetting the safety bit
    let addr = SAFETY_LOCATION;
    let new_value = 0;
    flc.write_32(addr, new_value).unwrap();
    delay.delay_ms(1000);

    pac::SCB::sys_reset();
}
