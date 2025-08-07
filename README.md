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
