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
use alloc::string::String;

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
}

pub struct Subscription {
    device_id: u32,
    channel: u32,
    start: u64,
    end: u64,
    keys: HashMap<String, [u8; 32]>,
}

use core::panic::PanicInfo;

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

        console.write_bytes(b"\r\n");
        console.write_bytes(b"PANIC PANIC\r\n");
        console.write_bytes(b"Going to reset bit :)\r\n");

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
