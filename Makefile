SWIFT ?= xcrun swiftc
PREFIX ?= /opt/homebrew/bin
BUILD_DIR := build
BIN := $(BUILD_DIR)/wifi-switch

.PHONY: all clean install check

all: $(BIN)

$(BIN): main.swift
	mkdir -p $(BUILD_DIR)
	$(SWIFT) -O -framework Security -o $(BIN) main.swift

clean:
	rm -rf $(BUILD_DIR)

install: $(BIN)
	install -d $(PREFIX)
	install -m 755 $(BIN) $(PREFIX)/wifi-switch

check: $(BIN)
	$(BIN) --help >/dev/null
