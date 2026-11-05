CARGO ?= cargo
.DEFAULT_GOAL := build
TARGET_DIR ?= target
BINARY ?= $(TARGET_DIR)/release/fidophir
DESTDIR ?=
PREFIX ?= /usr

.PHONY: build test integration integration-hid install
build:
	$(CARGO) build --locked --release --bin fidophir --target-dir $(TARGET_DIR)

test:
	bash tests/packaging.sh
	$(CARGO) test --locked --lib --target-dir $(TARGET_DIR)

integration:
	$(CARGO) build --locked --bin fidophir-integration --features integration-tests --target-dir $(TARGET_DIR)
	python3 tests/interop.py --binary $(abspath $(TARGET_DIR))/debug/fidophir-integration --expiry
	python3 tests/desktop.py --binary $(abspath $(TARGET_DIR))/debug/fidophir-integration

integration-hid:
	$(CARGO) build --locked --bin fidophir-integration --features integration-tests --target-dir $(TARGET_DIR)
	bash tests/hid_cli.sh $(abspath $(TARGET_DIR))/debug/fidophir-integration

# Staging only: no account creation, policy reload, device access or service start.
install:
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/libexec/fidophir
	install -Dm644 packaging/fidophir@.service $(DESTDIR)$(PREFIX)/lib/systemd/system/fidophir@.service
	install -Dm644 packaging/fidophir.sysusers $(DESTDIR)$(PREFIX)/lib/sysusers.d/fidophir.conf
	install -Dm644 packaging/fidophir.modules-load $(DESTDIR)$(PREFIX)/lib/modules-load.d/fidophir.conf
	install -Dm644 packaging/72-fidophir.rules $(DESTDIR)$(PREFIX)/lib/udev/rules.d/72-fidophir.rules
	install -Dm644 packaging/fidophir.target $(DESTDIR)$(PREFIX)/lib/systemd/system/fidophir.target
	install -Dm644 packaging/00-fidophir.preset $(DESTDIR)$(PREFIX)/lib/systemd/system-preset/00-fidophir.preset
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/user@.service.wants
	ln -sf ../fidophir@.service $(DESTDIR)$(PREFIX)/lib/systemd/system/user@.service.wants/fidophir@.service
	install -Dm755 packaging/fidophir-package-setup $(DESTDIR)$(PREFIX)/libexec/fidophir-package-setup
	install -Dm644 packaging/org.local.fidophir.policy $(DESTDIR)$(PREFIX)/share/polkit-1/actions/org.local.fidophir.policy
	install -Dm644 -t $(DESTDIR)$(PREFIX)/share/doc/fidophir README.md DESIGN.md VALIDATION.md
	install -Dm644 packaging/README.md $(DESTDIR)$(PREFIX)/share/doc/fidophir/packaging/README.md
	install -Dm644 -t $(DESTDIR)$(PREFIX)/share/licenses/fidophir LICENSE LICENSE-APACHE
