# Swarmui-Image-Encriptor

A security extension for [SwarmUI](https://github.com/mcmonkeyprojects/SwarmUI) that encrypts generated media directly in memory using authenticated **AES-256-GCM** before writing to disk, while keeping images fully visible and interactive in the web interface.

[![SwarmUI Compatible](https://img.shields.io/badge/SwarmUI-Extension-4b32c3.svg)](https://github.com/mcmonkeyprojects/SwarmUI)
[![Encryption](https://img.shields.io/badge/Cipher-AES--256--GCM-0052cc.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![KDF](https://img.shields.io/badge/KDF-PBKDF2--SHA256%20(100k)-00875a.svg)](https://en.wikipedia.org/wiki/PBKDF2)
[![License: MIT](https://img.shields.io/badge/License-MIT-gray.svg)](LICENSE)

---

## Overview

In multi-tenant, cloud-hosted, or shared execution environments (such as Kaggle or Google Colab), generated files written in raw format to the local filesystem are exposed to host-level scanners, file indexing jobs, or unauthorized inspection.

**Swarmui-Image-Encriptor** intercepts generation outputs directly in memory (RAM). When encryption is active, raw unencrypted media never touches the host storage: the data is converted, preview-indexed, encrypted with AES-256-GCM, and written to disk purely as binary ciphertext. When accessed through the SwarmUI web interface, an integrated HTTP middleware decrypts payloads on-the-fly in response to authorized sessions.

---

## Architecture & Data Flow

```
[ Stable Diffusion / ComfyUI Pipeline ]
                   │
                   ▼ (In-Memory Image Buffer)
         [ PostGenerate Hook ]
                   │
                   ├──> WebSocket Live Stream ──> Web Client (Rendered in Viewport)
                   │
                   ├──> Pre-cache Thumbnail & Metadata ──> Internal LiteDB (swarm_metadata.ldb)
                   │
                   ▼
         [ In-Memory AES-256-GCM Encryption ]
                   │
                   ▼ (Only Ciphertext Touches Storage)
         [ Disk Write: Output/YYYY-MM-DD/filename.png ] (SWARMENC Header + Ciphertext)
```

1. **Zero-Disk Exposure (`DoNotSave` Interception)**: The extension signals the SwarmUI generation engine to bypass raw disk saving. The browser receives the live result directly via WebSocket.
2. **Metadata & Preview Pre-caching**: Generation parameters (prompt, seed, model, etc.) and preview thumbnails are stored directly into SwarmUI's internal SQLite/LiteDB database (`swarm_metadata.ldb`). No plaintext `.swarm.json` metadata files with sensitive prompts are left on disk.
3. **In-Memory Encryption**: Image payloads are transformed and encrypted in RAM using AES-256-GCM with a unique salt and nonce per file.
4. **On-the-Fly Decryption Middleware**: When requesting an image (`/View/...` or `/Output/...`), ASP.NET Core middleware decrypts the file stream in memory for the active authenticated session.
5. **Fallback Watcher with Format Validation**: A background `FileSystemWatcher` acts as a secondary layer for files emitted outside the standard generation path. It enforces atomic access locks (`FileShare.None`) and format-specific boundary verification (PNG `IEND`, JPEG `EOI`, WebP `RIFF`) before encryption to prevent partial writes or truncated files.

---

## Technical Specifications

| Parameter | Value | Details |
| :--- | :--- | :--- |
| **Cipher** | `AES-256-GCM` | Authenticated Galois/Counter Mode (confidentiality + integrity verification) |
| **Key Derivation** | `PBKDF2-HMAC-SHA256` | 100,000 iterations |
| **Salt Length** | `16 bytes` | CSPRNG-generated (`RandomNumberGenerator.GetBytes`) per file |
| **Nonce (IV)** | `12 bytes` | Unique CSPRNG vector per file |
| **Auth Tag** | `16 bytes` | GCM authentication tag for tamper detection |
| **Header Overhead** | `53 bytes` | Standardized binary header prefix |

### Binary File Layout (`SWARMENC`)

Encrypted output files adopt the following binary structure:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Magic Bytes: "SWARMENC" (8 B)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x01)|           PBKDF2 Salt (Bytes 0..14)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Salt (B15)   |          AES-GCM Nonce / IV (12 B)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    GCM Auth Tag (16 B)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Payload ...                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Features

- **In-RAM Encryption Pipeline**: Prevents unencrypted image data and plaintext metadata files from ever reaching the storage medium.
- **Transparent Web UI Operation**: Generations, history browsing and prompt inspection ("Reuse Parameters") operate normally through automated in-memory decryption.
- **Dedicated Sidebar Interface (`Encryptor` Tab)**:
  - Master toggle switch (enabled by default).
  - Secret passcode/PIN input field with visibility toggling.
  - Interactive on-screen numeric keypad for touch or mouse input.
  - One-click random 8-digit PIN generator.
  - Client-side drag-and-drop file decryptor for inspecting or recovering files offline.
- **Dual-Layer State Persistence**:
  - Server-side: Stored persistently in `Data/image_encryptor_settings.json` across process restarts.
  - Client-side: Synced with browser `localStorage` for seamless multi-tab sessions.
- **Truncation Prevention**: File-locking guards and end-of-stream markers guarantee that files are never processed or corrupted prematurely.

---

## Installation

1. Place the extension directory into your SwarmUI installation:
   ```bash
   # From your SwarmUI root directory:
   git clone <repo-url> src/Extensions/Swarmui-Image-Encriptor
   ```

2. Confirm the directory structure:
   ```text
   src/Extensions/Swarmui-Image-Encriptor/
   ├── Assets/
   │   ├── image_encriptor.css
   │   └── image_encriptor.js
   ├── README.md
   ├── Swarmui-Image-Encriptor.csproj
   └── SwarmuiImageEncriptorExtension.cs
   ```

3. Launch or restart SwarmUI. The extension will automatically build and register on startup:
   ```bash
   ./launch-windows.bat  # Windows
   ./launch-linux.sh    # Linux
   ```

---

## Usage

1. Open the SwarmUI web interface.
2. Navigate to the **Encryptor** tab in the left sidebar (adjacent to `Inputs`).
3. Ensure **Enable Disk Encryption** is checked (enabled by default with initial passcode `1234`).
4. Set your custom passphrase or PIN. Any change automatically persists on disk and in browser storage.
5. Generate images as usual. Outputs will appear normally in the generation canvas and history, while the underlying files stored in `Output/` remain encrypted.
6. **Offline Decryption**: Drag any `.png`, `.jpg`, or `.webp` encrypted file into the dropzone in the Encryptor tab to decrypt and download it directly in the client.

> [!WARNING]
> Keep a safe record of your encryption passcode. Data encrypted with AES-256-GCM cannot be recovered if the passcode is lost.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
