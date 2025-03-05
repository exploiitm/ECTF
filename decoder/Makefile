BIN_NAME = ectf
board = 1
lock_dir =/tmp

default: release

clean:
	@rm -rf build
	@cargo clean

release: clean
	@mkdir -p build
	@echo $(DECODER_ID)
	@export DECODER_ID=$(DECODER_ID); cargo build --release
	@cp target/thumbv7em-none-eabihf/release/${BIN_NAME} build/max78000.elf
	@arm-none-eabi-objcopy --strip-all -O binary build/max78000.elf build/max78000.bin
	@echo "IMPORTANT: You MUST perform a power-on reset in order to flash new firmware after you have flashed a release build!"

lock: clean
	@LOCK_FILE="${lock_dir}/lock-${board}"; \
	echo $${LOCK_FILE}; \
	if [ -e "$$LOCK_FILE" ]; then \
		echo "Board ${board} is already locked"; \
		exit 1; \
	fi; \
	chmod +x board${board}.zsh; \
	zsh board${board}.zsh; \
	echo "Board ${board} is now locked"; \
	touch "$$LOCK_FILE";


unlock:
	@rm "./openocd.cfg"
	@rm "./openocd.gdb"
	@rm "${lock_dir}/lock-${board}"


