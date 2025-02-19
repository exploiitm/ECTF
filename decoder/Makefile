BIN_NAME = ectf
.PHONY: flash check_locks release clean

LOCK_DIR=/tmp
DEVICES=/dev/ttyACM1 /dev/ttyACM2 /dev/ttyACM3

clean:
	@rm -rf build
	@cargo clean

release: clean
	@mkdir -p build
	@cargo build --release
	@cp target/thumbv7em-none-eabihf/release/${BIN_NAME} build/max78000.elf
	@arm-none-eabi-objcopy -O binary build/max78000.elf build/max78000.bin




# Check which devices are in use and lock them
check_locks:
	@for d in $(DEVICES); do \
		if lsof $$d > /dev/null 2>&1; then \
			LOCK_FILE="$(LOCK_DIR)/lock-$$(basename $$d)"; \
			if [ ! -e $$LOCK_FILE ]; then \
				touch $$LOCK_FILE; \
				echo "Locking $$d (in use)"; \
			fi; \
		else \
			LOCK_FILE="$(LOCK_DIR)/lock-$$(basename $$d)"; \
			if [ -e $$LOCK_FILE ]; then \
				rm -f $$LOCK_FILE; \
				echo "Unlocking $$d (no longer in use)"; \
			fi; \
		fi; \
	done

# Find an available device (not locked or in use) and flash it
AVAILABLE_DEVICE := $(shell for d in $(DEVICES); do \
    if [ -e "$(LOCK_DIR)/lock-$$(basename $$d)" ]; then \
        echo "Device $$d is locked and not available." >&2; \
    elif lsof $$d > /dev/null 2>&1; then \
        echo "Device $$d is currently in use." >&2; \
    else \
        echo $$d; break; \
    fi; \
done)

flash: check_locks
	@if [ -n "$(AVAILABLE_DEVICE)" ]; then \
		LOCK_FILE="$(LOCK_DIR)/lock-$$(basename $(AVAILABLE_DEVICE))"; \
		touch $$LOCK_FILE; \
		echo "Flashing $(AVAILABLE_DEVICE)..."; \
		python3 tools/remote.py UPLOAD $(subst /dev/ttyACM,,$(AVAILABLE_DEVICE)); \
		sleep 5; \
		python3 -m ectf25.utils.flash ./build/max78000.bin $(AVAILABLE_DEVICE); \
		rm -f $$LOCK_FILE; \
		echo "Flash complete!"; \
	else \
		echo "No available device to flash (all are locked or in use)."; \
	fi

