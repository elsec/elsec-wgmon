BINARY     := target/release/wgmon
INSTALL_BIN := /usr/local/bin/wgmon
UNIT_SRC   := wgmon@.service
UNIT_DST   := /etc/systemd/system/wgmon@.service
CONFIG_DIR := /etc/wgmon

.PHONY: build install uninstall

build:
	cargo build --release

install: build
	install -Dm755 $(BINARY) $(INSTALL_BIN)
	install -Dm644 $(UNIT_SRC) $(UNIT_DST)
	mkdir -p $(CONFIG_DIR)
	systemctl daemon-reload
	@echo "Installed. Create $(CONFIG_DIR)/<profile>.toml then run:"
	@echo "  systemctl enable --now wgmon@<profile>.service"

uninstall:
	systemctl disable --now 'wgmon@*.service' 2>/dev/null || true
	rm -f $(INSTALL_BIN) $(UNIT_DST)
	systemctl daemon-reload
	@echo "Note: $(CONFIG_DIR) left intact — remove manually if no longer needed."
