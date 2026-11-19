#!/usr/bin/env bash
set -euo pipefail

MODULE_NAME="tor_hook"
KO_FILE="./${MODULE_NAME}.ko"

if [[ $EUID -ne 0 ]]; then
   echo "Error: Run this script as root (sudo $0 [load|unload])"
   exit 1
fi

ACTION="${1:-load}"

if [[ "$ACTION" == "unload" ]]; then
    echo "[*] Unloading ${MODULE_NAME}..."
    rmmod "${MODULE_NAME}" 2>/dev/null || echo "[!] Module not loaded."
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null
    echo "[+] Module unloaded and IPv6 restored."
    exit 0
fi

if [[ ! -f "$KO_FILE" ]]; then
    echo "[*] Building ${KO_FILE}..."
    make
fi

# Detect Tor daemon UID
TOR_USER=""
for u in debian-tor tor _tor; do
    if id "$u" &>/dev/null; then
        TOR_USER="$u"
        break
    fi
done

if [[ -z "$TOR_USER" ]]; then
    echo "Error: Could not find Tor system user (debian-tor or tor). Is Tor installed?"
    exit 1
fi

TOR_UID=$(id -u "$TOR_USER")
echo "[*] Detected Tor user '${TOR_USER}' (UID: ${TOR_UID})"

echo "[*] Loading required netfilter modules..."
modprobe nf_conntrack
modprobe nf_nat

echo "[*] Disabling IPv6 to prevent clearnet leaks..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null

echo "[*] Inserting ${KO_FILE}..."
insmod "$KO_FILE" tor_uid="$TOR_UID"

echo "[+] ${MODULE_NAME} active! Verify via: curl https://torproject.org"
