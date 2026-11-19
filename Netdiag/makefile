PKG_NAME    := netdiag
PKG_VERSION := 2.0.0
PKG_ARCH    := all
DIST_DIR    := dist
BUILD_DIR   := build/deb
DEB_FILE    := $(DIST_DIR)/$(PKG_NAME)_$(PKG_VERSION)_$(PKG_ARCH).deb

PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
LIBDIR      := $(PREFIX)/lib/$(PKG_NAME)
SYSTEMDDIR  := /lib/systemd/system
ETCDIR      := /etc/$(PKG_NAME)

.PHONY: all install uninstall lint test deb clean

all: lint test

install:
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR)
	install -m 0755 bin/netdiag $(DESTDIR)$(BINDIR)/netdiag
	install -m 0644 lib/*.sh $(DESTDIR)$(LIBDIR)/
	@echo "Installed $(PKG_NAME) to $(DESTDIR)$(BINDIR)/netdiag"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/netdiag
	rm -rf $(DESTDIR)$(LIBDIR)
	@echo "Uninstalled $(PKG_NAME)"

lint:
	shellcheck -x bin/netdiag lib/*.sh

test:
	bats tests/netdiag.bats

deb:
	@command -v dpkg-deb >/dev/null 2>&1 || { echo "Error: dpkg-deb is required to build .deb packages." >&2; exit 1; }
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/DEBIAN $(DIST_DIR)

	# 1. Stage binaries and libraries under /usr (standard distro prefix)
	$(MAKE) install DESTDIR=$(BUILD_DIR) PREFIX=/usr

	# 2. Stage default config & systemd units if present
	install -d $(BUILD_DIR)$(ETCDIR)
	@if [ ! -f $(BUILD_DIR)$(ETCDIR)/netdiag.conf ]; then \
		printf '# Default netdiag configuration\nTARGET="1.1.1.1"\nPORT="443"\n' > $(BUILD_DIR)$(ETCDIR)/netdiag.conf; \
	fi
	@if [ -d deploy/systemd ]; then \
		install -d $(BUILD_DIR)$(SYSTEMDDIR); \
		install -m 0644 deploy/systemd/*.service $(BUILD_DIR)$(SYSTEMDDIR)/ 2>/dev/null || true; \
		install -m 0644 deploy/systemd/*.timer $(BUILD_DIR)$(SYSTEMDDIR)/ 2>/dev/null || true; \
	fi

	# 3. Stage documentation & copyright
	install -d $(BUILD_DIR)/usr/share/doc/$(PKG_NAME)
	install -m 0644 README.md $(BUILD_DIR)/usr/share/doc/$(PKG_NAME)/README.md
	install -m 0644 LICENSE $(BUILD_DIR)/usr/share/doc/$(PKG_NAME)/copyright

	# 4. Generate DEBIAN/control metadata
	@INSTALLED_SIZE=$$(du -sk $(BUILD_DIR) | awk '{print $$1}'); \
	cat > $(BUILD_DIR)/DEBIAN/control <<EOF
	Package: $(PKG_NAME)
	Version: $(PKG_VERSION)
	Section: net
	Priority: optional
	Architecture: $(PKG_ARCH)
	Maintainer: Network Engineering <netops@example.com>
	Depends: bash (>= 4.2), iproute2, iputils-ping, coreutils, gawk
	Recommends: curl, jq, mtr-tiny
	Installed-Size: $${INSTALLED_SIZE}
	Description: Linux network diagnostic and latency debugging CLI
	 Modular Bash diagnostic utility that measures DNS, ICMP, TCP, and TLS
	 latency, reads /proc/net SNMP counters, detects proxy/VPN ping anomalies,
	 and exports Prometheus Node Exporter textfile metrics.
	EOF

	# 5. Mark configuration files so upgrades preserve user edits
	echo "$(ETCDIR)/netdiag.conf" > $(BUILD_DIR)/DEBIAN/conffiles

	# 6. Create postinst & prerm maintainer scripts
	cat > $(BUILD_DIR)/DEBIAN/postinst <<'EOF'
	#!/bin/sh
	set -e
	if [ -d /run/systemd/system ]; then
	    systemctl daemon-reload >/dev/null 2>&1 || true
	fi
	exit 0
	EOF

	cat > $(BUILD_DIR)/DEBIAN/prerm <<'EOF'
	#!/bin/sh
	set -e
	if [ "$$1" = "remove" ] && [ -d /run/systemd/system ]; then
	    systemctl stop netdiag-exporter.timer >/dev/null 2>&1 || true
	    systemctl disable netdiag-exporter.timer >/dev/null 2>&1 || true
	fi
	exit 0
	EOF

	chmod 0755 $(BUILD_DIR)/DEBIAN/postinst $(BUILD_DIR)/DEBIAN/prerm

	# 7. Build the .deb archive (root:root ownership)
	dpkg-deb --build --root-owner-group $(BUILD_DIR) $(DEB_FILE)
	@echo "Built package: $(DEB_FILE)"

clean:
	rm -rf build $(DIST_DIR)
