//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.
//! For many projects this is optional, as the linker always searches the
//! project root directory -- wherever `Cargo.toml` is. However, if you
//! are using a workspace or have a more complicated build setup, this
//! build script becomes required. Additionally, by requesting that
//! Cargo re-run the build script whenever `memory.x` is changed,
//! updating `memory.x` ensures a rebuild of the application with the
//! new memory settings.
//!
//! The build script also sets the linker flags to tell it which link script to use.

use hex;
use serde_json;
use sha3::{Digest, Sha3_256};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");

    // Specify linker arguments.

    // `--nmagic` is required if memory section addresses are not aligned to 0x10000,
    // for example the FLASH and RAM sections in your `memory.x`.
    // See https://github.com/rust-embedded/cortex-m-quickstart/pull/95
    println!("cargo:rustc-link-arg=--nmagic");

    // Set the linker script to the one provided by cortex-m-rt.
    println!("cargo:rustc-link-arg=-Tlink.x");

    let decoder_id = std::env::var("DECODER_ID").unwrap();
    let SECRET_FILE = "../../global.secrets";
    println!("cargo:rerun-if-changed={}", SECRET_FILE);
    // Loading in secrets.json
    let secrets = fs::read_to_string(SECRET_FILE).expect("Failed to read secrets.json");
    let json: serde_json::Value =
        serde_json::from_str(&secrets).expect("Invalid JSON format in secrets.json");

    // Generate Rust code with constants
    let mut rust_code = String::new();
    rust_code.push_str(&format!("pub const DECODER_ID: u32 = {};", decoder_id));
    rust_code.push_str("// Auto-generated file, do not edit manually!\n");

    if let serde_json::Value::Object(map) = json {
        rust_code.push_str(
            "fn get_key(key: &str) -> Option<&'static [u8; 32]> {
            match key { \n",
        );
        for (key, value) in map {
            if let Some(val) = value.as_str() {
                let hex_val = hex::decode(val);
                let bytes = hex_val.unwrap();
                let array = format!("{:?}", bytes);
                if key == "K0" {
                    rust_code.push_str(&format!("\"{}\" => Some(&{}),\n", key, array));
                } else if key == "Ks" {
                    // let mut hasher = Sha3_256::new();
                    // hasher.update(val);
                    // let hard_device_id = device_id.to_string();
                    //
                    // hasher.update(hard_device_id);
                    // let k10 = hasher.finalize();
                    let hex_val = hex::decode(val);
                    let bytes = hex_val.unwrap();
                    let mut hasher = Sha3_256::new();
                    hasher.update(&bytes);

                    let hard_device_id: u32 = if &decoder_id[0..2] == "0x" {
                        u32::from_str_radix(&decoder_id[2..], 16).unwrap()
                    } else {
                        decoder_id.parse().unwrap()
                    };
                    let hard_device_id = hard_device_id.to_string();
                    hasher.update(&hard_device_id);
                    let k10: [u8; 32] = hasher.finalize().try_into().unwrap();
                    let array = format!("{:?}", k10);
                    rust_code.push_str(&format!("\"{}\" => Some(&{}),\n", "Ks", array));
                }
            }
        }

        println!("{}", rust_code);
    }
    rust_code.push_str(
        "_ => None,
            }
        }",
    );
    let out_dir = env::var("OUT_DIR").unwrap();
    let rust_code_2 = rust_code.clone();

    fs::write(format!("{}/secrets.rs", out_dir), rust_code).expect("Failed to write secrets.rs");
    fs::write(format!("{}/debug.rs", out_dir), rust_code_2).expect("Failed to write secrets.rs");
}
