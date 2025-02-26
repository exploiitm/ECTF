#![no_std]

pub const CHANNEL_ID_SIZE: usize = 4;
pub const TIMESTAMP_SIZE: usize = 8;
pub const MAX_NUM_CHANNELS: usize = 8;

use cipher::KeyInit;
use core::arch::asm;
use core::array;
use max7800x_hal::{
    self as hal,
    gpio::{Af1, InputOutput},
    pac::{Peripherals, SCB, Uart0},
    uart::BuiltUartPeripheral,
};

use hal::pac;

use sha3::{Digest, Sha3_256};

extern crate alloc;
use alloc::format;

use segtree_kdf::{self, Key, KeyHasher, MAX_COVER_SIZE};
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
}

pub struct SHA256Hasher {
    pub key_left: Key,
    pub key_right: Key,
}

impl KeyHasher for SHA256Hasher {
    fn new() -> Self {
        let key_left_base: u32 = 0xDEADBEEF;
        let key_left = key_left_base.to_le_bytes().repeat(8).try_into().unwrap();
        let key_right_base: u32 = 0xC0D3D00D;
        let key_right = key_right_base.to_le_bytes().repeat(8).try_into().unwrap();

        SHA256Hasher {
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

        mac.finalize().as_slice().try_into().unwrap()
    }
}

pub struct Subscription {
    pub channel: u32,
    pub start: u64,
    pub end: u64,
    pub kdf: segtree_kdf::SegtreeKDF<SHA256Hasher>,
}

pub struct Subscriptions {
    pub size: u8,
    pub subscriptions: [Option<Subscription>; MAX_NUM_CHANNELS],
}

impl Subscription {
    pub fn new(channel: u32, start: u64, end: u64, keys: &[u8]) -> Self {
        let num_nodes_bytes = keys[0..8].try_into().unwrap();
        let num_nodes = u64::from_le_bytes(num_nodes_bytes) as usize;
        let keys = &keys[8..];

        let mut cover: [Option<segtree_kdf::Node>; segtree_kdf::MAX_COVER_SIZE] =
            array::from_fn(|_| None);

        for i in 0..num_nodes {
            let id_bytes = keys[i * 40..i * 40 + 8].try_into().unwrap();
            let id = u64::from_le_bytes(id_bytes);
            let key_bytes = &keys[i * 40 + 8..i * 40 + 40];
            let node = segtree_kdf::Node {
                id,
                key: key_bytes.try_into().unwrap(),
            };
            cover[i] = Some(node);
        }

        let mut last_layer: [Option<segtree_kdf::Node>; 2] = array::from_fn(|_| None);
        let num_leaves = keys.len() / 40 - num_nodes;

        for i in 0..num_leaves {
            let id_bytes = keys[(num_nodes + i) * 40..(num_nodes + i) * 40 + 8]
                .try_into()
                .unwrap();
            let id = u64::from_le_bytes(id_bytes);
            let key_bytes = keys[(num_nodes + i) * 40 + 8..(num_nodes + i) * 40 + 40]
                .try_into()
                .unwrap();
            let node = segtree_kdf::Node { id, key: key_bytes };
            last_layer[i] = Some(node);
        }
        let kdf = segtree_kdf::SegtreeKDF::<SHA256Hasher>::new(cover, last_layer);

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
    pub fn add_subscription(&mut self, sub: Subscription) {
        for i in 0..MAX_NUM_CHANNELS {
            match &self.subscriptions[i] {
                Some(subscription) => {
                    if subscription.channel == sub.channel {
                        self.subscriptions[i] = Some(sub);
                        return;
                    }
                }
                None => {
                    self.subscriptions[i] = Some(sub);
                    self.size += 1;
                    return;
                }
            }
        }
        panic!("It's okay bro, you tried");
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
        }
    }

    pub fn set_safety_bit(&mut self) -> Result<u32, hal::flc::FlashError> {
        let addr = 0x10045ff8;
        let new_value = 0xffffffff; // Only extracting last 6 bits
        self.flc.write_32(addr, new_value)?;
        Ok(new_value)
    }
    pub fn reset_safety_bit(&mut self) -> Result<u32, hal::flc::FlashError> {
        let addr = 0x10045ff8;
        let new_value = 0; // Only extracting last 6 bits
        self.flc.write_32(addr, new_value)?;
        Ok(new_value)
    }

    pub fn is_safety_bit_set(&mut self) -> bool {
        let last_32bit_addr = 0x10045ff8;
        let current_value = self.flc.read_32(last_32bit_addr).unwrap();
        if (current_value as u8) == 0xFF {
            return true;
        } else {
            return false;
        }
    }

    pub fn lockdown(&mut self) {
        self.console.write_bytes(b"LOCDOWN INITIATED LMAO NOOB\r\n");
        self.delay.delay_ms(3000);
        let addr = 0x10045ff8;
        unsafe { self.flc.erase_page(addr).unwrap() };

        self.led_pins.led_r.set_high();
        self.delay.delay_ms(3000);
        self.led_pins.led_r.set_low();
        self.delay.delay_ms(3000);
    }
}

#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! {
    unsafe {
        let peripherals: Peripherals = Peripherals::steal();
        let core: pac::CorePeripherals = pac::CorePeripherals::steal();
        let mut gcr = hal::gcr::Gcr::new(peripherals.gcr, peripherals.lpgcr);
        //Initialize the Internap Primary Oscillator (IPO)
        let ipo = hal::gcr::clocks::Ipo::new(gcr.osc_guards.ipo).enable(&mut gcr.reg);
        let clks = gcr.sys_clk.set_source(&mut gcr.reg, &ipo).freeze();
        let mut delay = cortex_m::delay::Delay::new(core.SYST, clks.sys_clk.frequency);
        let pins = hal::gpio::Gpio2::new(peripherals.gpio2, &mut gcr.reg).split();

        let mut led_r = pins.p2_0.into_input_output();
        let mut led_g = pins.p2_1.into_input_output();
        let mut led_b = pins.p2_2.into_input_output();
        // Use VDDIOH as the power source for the RGB LED pins (3.0V)
        // Note: This HAL API may change in the future
        led_r.set_power_vddioh();
        led_g.set_power_vddioh();
        led_b.set_power_vddioh();

        let gpio0_pins = hal::gpio::Gpio0::new(peripherals.gpio0, &mut gcr.reg).split();
        // Configure UART to host computer with 115200 8N1 settings
        let rx_pin = gpio0_pins.p0_0.into_af1();
        let tx_pin = gpio0_pins.p0_1.into_af1();

        let flc = hal::flc::Flc::new(peripherals.flc, clks.sys_clk);

        //initializing the console
        let console =
            hal::uart::UartPeripheral::uart0(peripherals.uart0, &mut gcr.reg, rx_pin, tx_pin)
                .baud(115200)
                .clock_pclk(&clks.pclk)
                .parity(hal::uart::ParityBit::None)
                .build();

        let DEBUG_HEADER: [u8; 2] = [b'%', b'G'];
        console.write_bytes(&DEBUG_HEADER);
        delay.delay_ms(1000);
        let message = b"board panicked";
        let message_len = message.len() as u16;
        let message_len_bytes = message_len.to_le_bytes();
        console.write_bytes(&message_len_bytes);
        console.write_bytes(message);
        console.flush_tx();

        let addr = 0x10045ff8;
        let new_value = 0; // Only extracting last 6 bits
        flc.write_32(addr, new_value).unwrap();
        delay.delay_ms(1000);

        console.write_bytes(b"Bit reset :)\r\n");
        console.flush_tx();

        loop {}
    }
}
