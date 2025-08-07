# ESP32_MIDI
ESP32-based wireless endpoint that plays MIDI data on connected instruments.

## Concept

An ESP32 module attaches to a simple MIDI In/Out interface and outputs MIDI commands either directly from a remote system or from an uploaded MIDI file.

## Development

This repository contains a minimal ESP-IDF project with a custom partition table providing a 2 MB application slot and a 1 MB SPIFFS partition for MIDI storage.

## Features

* Captive-style Wi-Fi configuration portal with SoftAP fallback.
* HTTPS server using the ESP-IDF `esp_https_server` with a self-signed certificate or user-uploaded certificate/key.
* Multipart file upload endpoint that stores uploaded files to the SPIFFS partition.

## Low-memory configuration

The project targets ESP32 modules with limited RAM and flash. The following build-time
options can be tuned via `menuconfig` or `sdkconfig.defaults`:

* `CONFIG_MIDI_MAX_EVENTS` – maximum number of parsed MIDI events held in RAM.
  Reduce this value for smaller tracks or increase for complex files.
* `CONFIG_UPLOAD_BUF_SIZE` – chunk size used for file and OTA uploads. Smaller
  values lower RAM usage at the cost of transfer speed.

Uploaded files are written in chunks to SPIFFS so large transfers do not require
additional heap. Ensure that uploaded files fit within the 1 MB SPIFFS partition.

## Toolchain setup

1. Install the [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
   toolchain and export the environment:
   ```bash
   git clone --recursive https://github.com/espressif/esp-idf.git
   ./esp-idf/install.sh esp32
   . ./esp-idf/export.sh
   ```
2. Clone this repository into the `esp-idf` workspace and install the Python
   requirements if prompted.

## Flashing

Connect the ESP32 over USB and run:

```bash
idf.py set-target esp32
idf.py build
idf.py -p <PORT> flash monitor
```

Replace `<PORT>` with the serial port used by your board.

## Web interface

On first boot the device starts a SoftAP named `ESP32_MIDI` with password
`password`.  Visit [https://192.168.4.1](https://192.168.4.1) to open the
configuration portal and enter Wi‑Fi credentials.  After connecting to the
infrastructure network the same HTTPS interface allows uploading MIDI files and
controlling playback.

## HTTP API

* `POST /upload` – multipart file upload stored under `/spiffs`.
* `GET /track?file=<name>&track=<n>` – load track `n` from the uploaded file.
* `GET /play`, `GET /pause`, `GET /stop` – playback control.
* `POST /midi` – send raw MIDI bytes encoded as hexadecimal pairs.
* `GET /ws` – WebSocket endpoint for streaming MIDI messages.
* UDP port `5005` – accept raw MIDI packets over the network.

All state‑changing requests require an `X-Auth-Token` header set to `midi123`.

## Partitioning and OTA

The custom partition table provides:

| Name     | Size   | Notes                              |
|----------|--------|------------------------------------|
| `nvs`    | 16 KB  | Non‑volatile storage for settings. |
| `phy_init` | 4 KB | Wi‑Fi calibration data.            |
| `factory` | 2 MB  | Application slot.                  |
| `storage` | 1 MB  | SPIFFS partition for MIDI files.   |

Firmware updates can be uploaded using `POST /ota` with a multipart body.  The
image is written to the application slot and the device reboots after a
successful transfer.  An automatic OTA task periodically fetches firmware from
`UPDATE_URL` (default one hour interval) and applies it when a newer version is
available.
