#!/usr/bin/env bash
# Reload a freshly-built wd_dma.ko safely.
set -euo pipefail

KO=${1:-wd_dma.ko}                          # path to the new ko
DST_DIR=/lib/modules/$(uname -r)/extra

echo "[+] Installing $KO to $DST_DIR"
sudo mkdir -p "$DST_DIR"
sudo cp "$KO" "$DST_DIR/"
sudo depmod -a                              # update modules.dep

if lsmod | grep -q '^wd_dma' ; then
    echo "[+] Unloading current wd_dma"
    sudo modprobe -r wd_dma || {
        echo "[!] wd_dma is still busy (open fd or mmap) – abort"
        exit 1
    }
fi

echo "[+] Loading new wd_dma"
sudo modprobe wd_dma

# set up boot-time autoload once
if [ ! -f /etc/modules-load.d/wd_dma.conf ] ; then
    echo "[+] Enabling boot-time autoload"
    echo wd_dma | sudo tee /etc/modules-load.d/wd_dma.conf > /dev/null
fi

echo "[+] wd_dma reloaded OK"
