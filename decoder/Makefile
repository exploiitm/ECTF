BIN_NAME = ectf

default: release

clean:
	@rm -rf build
	@cargo clean

release: clean
	@mkdir -p build
	@cargo build --release
	@cp target/thumbv7em-none-eabihf/release/${BIN_NAME} build/max78000.elf
	@arm-none-eabi-objcopy --strip-all -O binary build/max78000.elf build/max78000.bin
	@echo "IMPORTANT: You MUST perform a power-on reset in order to flash new firmware after you have flashed a release build!"

