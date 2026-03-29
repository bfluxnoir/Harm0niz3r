FROM mcr.microsoft.com/devcontainers/python:3.11-bullseye

# ── System packages ──────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # ADB (Android Debug Bridge)
    android-tools-adb \
    # USB device access helpers
    usbutils \
    libusb-1.0-0 \
    # General utilities
    curl \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ── HDC (HarmonyOS Device Connector) ─────────────────────────────────────────
# HDC is distributed as part of the HarmonyOS SDK and must be downloaded manually.
# After starting this container, run the setup script:
#   bash .devcontainer/install_hdc.sh
# Official docs: https://developer.huawei.com/consumer/en/doc/harmonyos-guides-V5/ide-command-line-hdc-V5

# ── ADB daemon auto-start note ────────────────────────────────────────────────
# ADB server will start automatically when adb commands are first invoked.
# For USB device passthrough, make sure to run the container with --privileged
# and --network=host (already set in devcontainer.json).

# ── Shell prompt label ────────────────────────────────────────────────────────
RUN echo 'export PS1="(harm0niz3r) $PS1"' >> /etc/bash.bashrc
