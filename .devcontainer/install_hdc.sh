#!/usr/bin/env bash
# ============================================================
# install_hdc.sh  –  Install Huawei HDC (HarmonyOS Device Connector)
# Run this ONCE inside the dev container after it first starts:
#   bash .devcontainer/install_hdc.sh
# ============================================================

set -e

HDC_VERSION="3.1.0.2"
HDC_URL="https://developer.huawei.com/consumer/cn/download/hdc"    # Update URL to actual release
INSTALL_DIR="/usr/local/bin"

echo "[*] HDC auto-installer placeholder"
echo ""
echo "    HDC must be downloaded manually from the Huawei DevEco Studio SDK."
echo "    Steps:"
echo "    1. Download the HarmonyOS SDK from:"
echo "       https://developer.huawei.com/consumer/en/deveco-studio/"
echo "    2. Locate hdc (Linux) inside: sdk/HarmonyOS-NEXT/openharmony/toolchains/"
echo "    3. Copy it to /usr/local/bin/hdc"
echo "    4. chmod +x /usr/local/bin/hdc"
echo ""
echo "    Once done, verify with: hdc version"
