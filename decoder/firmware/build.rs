//! This build script copies the `memory.x` file from the crate root into
//! a directory where the linker can always find it at build time.

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use hex;
use serde_json;
use sha3::{Digest, Sha3_256};

fn main() {
    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());

    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rustc-link-arg=--nmagic");
    println!("cargo:rustc-link-arg=-Tlink.x");

    let decoder_id = std::env::var("DECODER_ID").unwrap();
    let secret_file = "../../global.secrets";
    println!("cargo:rerun-if-changed={}", secret_file);

    let secrets = fs::read_to_string(secret_file).expect("Failed to read global.secrets");
    let json: serde_json::Value =
        serde_json::from_str(&secrets).expect("Invalid JSON format in global.secrets");

    // Generate Rust code with constants
    let mut rust_code = String::new();
    rust_code.push_str(&format!("const DECODER_ID: u32 = {};", decoder_id));
    rust_code.push_str("// Auto-generated file, do not edit manually!\n");

    if let serde_json::Value::Object(map) = json {
        let value = map.get("Kpu").unwrap().as_str().unwrap();
        let hex_val = hex::decode(value);
        let value = hex_val.unwrap();
        rust_code.push_str(&format!("const KPU: [u8; 32] = {:?}", value));
        rust_code.push_str(";\n");
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
    }

    rust_code.push_str(
        "_ => None,
            }
        }",
    );
    let out_dir = env::var("OUT_DIR").unwrap();
    let code2 = rust_code.clone();
    fs::write(format!("{}/secrets.rs", out_dir), rust_code).expect("Failed to write secrets.rs");
    fs::write(format!("{}/nigger..rs", out_dir), code2).expect("Failed to write secrets.rs");
}
