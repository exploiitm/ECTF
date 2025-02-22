#![no_std]

use max7800x_hal::{
    self as hal,
    gpio::{Af1, InputOutput},
    pac::{Peripherals, Uart0},
    uart::BuiltUartPeripheral,
};

use hal::pac;

use hashbrown::HashMap;

extern crate alloc;
use alloc::{string::String, vec};

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

pub struct Subscription {
    device_id: u32,
    channel: u32,
    start: u64,
    end: u64,
    keys: vec::Vec<u8>,
}

pub struct Subscriptions{
    subscriptions: HashMap<u32, Option<Subscription>>,
}

impl Subscriptions {
    pub fn new() -> Self {
        Subscriptions {
            subscriptions: HashMap::new(),
        }
    }
    /// Adds a subscription to the given channel_id in the HashMap.
    ///
    /// The HashMap key is the channel_id of the subscription, and the value is
    /// the subscription itself.
    pub fn add_subscription(&mut self,sub: Subscription) {
        self.subscriptions.insert(sub.channel, Some(sub));
    }

    pub fn list_subscriptions(&self) -> vec::Vec<u8> {
        let num_channels = self.subscriptions.len() as u32;
        let mut message = vec![0u8; 4 + (num_channels as usize) * (16+4)];
        let num_channels_bytes = num_channels.to_le_bytes();
        message[0..4].copy_from_slice(&num_channels_bytes);
        let mut i = 4;
        for (sub_id, sub) in &self.subscriptions {
            let channel_id_bytes = sub_id.to_le_bytes();
            message[i..(i+4)].copy_from_slice(&channel_id_bytes);
            i += 4;
            let sub = sub.as_ref().unwrap();
            let start_bytes = sub.start.to_le_bytes();
            message[i..(i+8)].copy_from_slice(&start_bytes);
            i += 8;
            let end_bytes = sub.end.to_le_bytes();
            message[i..(i+8)].copy_from_slice(&end_bytes);
            i += 8;

        }

        message
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
        // LED blink loop
        loop {
            led_r.set_high();
            delay.delay_ms(500);
            led_g.set_high();
            delay.delay_ms(500);
            led_b.set_high();
            delay.delay_ms(500);
            led_r.set_low();
            delay.delay_ms(500);
            led_g.set_low();
            delay.delay_ms(500);
            led_b.set_low();
            delay.delay_ms(500);
        }
    }
}
