<div align="center">

# 🔒 Image Encryptor Extension for SwarmUI

**A modular, high-security disk encryption extension for [SwarmUI](https://github.com/mcmonkeyprojects/SwarmUI).**

[![SwarmUI Compatible](https://img.shields.io/badge/SwarmUI-Extension-purple.svg?style=for-the-badge&logo=github)](https://github.com/mcmonkeyprojects/SwarmUI)
[![Encryption](https://img.shields.io/badge/AES--256--GCM-Authenticated-blue.svg?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Key Derivation](https://img.shields.io/badge/PBKDF2-100k%20Iterations-green.svg?style=for-the-badge)](https://en.wikipedia.org/wiki/PBKDF2)
[![Vibe Coded](https://img.shields.io/badge/100%25-Vibe%20Coded-ff69b4.svg?style=for-the-badge&logo=sparkles)](#-vibe-coded)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

<br />

> ⚡ **100% Vibe Coded** — Built via AI vibe coding, thoroughly reviewed and battle-tested by a human developer.

</div>

---

## 📖 Overview

**Image Encryptor** seamlessly integrates into SwarmUI to protect generated images directly at the disk level. When active, generated outputs are instantly encrypted using authenticated **AES-256-GCM** encryption before saving to your output folder, while remaining fully visible and interactive in the SwarmUI web viewport.

> [!NOTE]
> Images generated during an active session render normally in your browser's viewport and batch strip. On disk (in `Output/`), files are securely scrambled into encrypted binary format (`.enc` or encrypted `.png`).

---

## ✨ Features

- 🔒 **Real-Time Disk Encryption**: Automatic, transparent encryption of newly generated images upon saving to disk.
- 🎚️ **Instant Toggle**: Dedicated switch in the UI to enable or disable encryption on-the-fly.
- 👁️ **Seamless UI Viewing**: Generated images display live in the SwarmUI viewport without exposing unencrypted files on disk.
- 🎛️ **Integrated Sidebar Tab (`🔒 Encryptor`)**: Positioned right next to the `Inputs` tab for fast access:
  - **Main Toggle**: Turn encryption ON or OFF effortlessly.
  - **Secret Passphrase / PIN Input**: Masked password field supporting custom passphrases or numeric PINs.
  - **Interactive Touch Keypad**: On-screen 0-9 keypad designed for quick mouse or touch entry.
  - **Random PIN Generator**: One-click generation of secure 8-digit random PINs.
  - **Real-Time Status Indicator**:
    - 🟢 **Encryption Active (AES-256)** — Encryption enabled with valid secret key set.
    - 🟡 **Enabled (Enter Code or PIN)** — Encryption enabled, waiting for secret key input.
    - ⚪ **Encryption Disabled** — Encryption turned OFF (standard saving).
  - **Drag & Drop Decryptor**: Built-in dropzone to instantly decrypt and view `.png`/`.enc` encrypted files directly inside the browser.

---

## 🛠️ Technical Specifications

This extension enforces enterprise-grade cryptographic standards to ensure data integrity and confidentiality:

| Parameter | Specification | Description |
| :--- | :--- | :--- |
| **Cipher Algorithm** | `AES-256-GCM` | Authenticated Galois/Counter Mode (confidentiality & tamper protection) |
| **Key Derivation** | `PBKDF2` | HMAC-SHA256 with **100,000 iterations** |
| **Salt** | `16 Bytes` | Cryptographically secure random salt generated per file |
| **Nonce / IV** | `12 Bytes` | Unique random initialization vector generated per file |
| **Auth Tag** | `16 Bytes` | Ensures files cannot be modified without detection |

### 📦 Binary Header Format

Encrypted files created by this extension contain a standardized 53-byte binary header followed by the encrypted ciphertext:

```
+------------------+---------+--------------------+--------------------+--------------------+--------------------+
| Magic Bytes      | Version | PBKDF2 Salt        | AES-GCM Nonce (IV) | Auth Tag           | Ciphertext         |
| "SWARMENC"       | (0x01)  | (16 bytes)         | (12 bytes)         | (16 bytes)         | (Variable)         |
| Bytes 0..7       | Byte 8  | Bytes 9..24        | Bytes 25..36       | Bytes 37..52       | Bytes 53..End      |
+------------------+---------+--------------------+--------------------+--------------------+--------------------+
```

| Offset (Bytes) | Field Name | Data / Type | Purpose |
| :---: | :--- | :--- | :--- |
| `0 .. 7` | **Magic Header** | `SWARMENC` (`0x53 0x57 0x41 0x52 0x4D 0x45 0x4E 0x43`) | Identifies file format |
| `8` | **Version** | `0x01` | Header format version identifier |
| `9 .. 24` | **Salt** | 16-byte random byte array | Salt for PBKDF2 key derivation |
| `25 .. 36` | **Nonce (IV)** | 12-byte random byte array | AES-GCM initialization vector |
| `37 .. 52` | **Auth Tag** | 16-byte authentication tag | Verification tag for tamper protection |
| `53 .. end` | **Ciphertext** | Encrypted image payload | Standard image data encrypted with AES-256-GCM |

---

## 🚀 Installation & Usage

### Installation

1. Copy or clone the `ImageEncryptor` extension folder into your SwarmUI installation under:
   ```text
   SwarmUI/src/Extensions/ImageEncryptor/
   ```

2. Ensure the directory structure matches:
   ```text
   SwarmUI/src/Extensions/ImageEncryptor/
   ├── Assets/
   │   ├── image_encryptor.css
   │   └── image_encryptor.js
   ├── ImageEncryptor.csproj
   └── ImageEncryptorExtension.cs
   ```

3. Launch SwarmUI using your standard startup script (`launch-dev.bat`, `launch-windows.bat`, or `launch-linux.sh`).

### Usage Guide

1. Open the SwarmUI Web Interface.
2. Select the **🔒 Encryptor** tab on the left sidebar (located next to `Inputs`).
3. Switch **Enable Disk Encryption** to **ON**.
4. Enter your desired **Secret Passphrase/PIN**, or click **Generate Random PIN**.
5. Start generating images:
   - In SwarmUI, preview images render normally.
   - On disk in `Output/`, saved images are safely encrypted with AES-256-GCM.
6. To decrypt an encrypted image offline or from disk, drag and drop the `.png` or `.enc` file into the **Drag & Drop Decryptor** area within the Encryptor tab.

> [!IMPORTANT]
> Make sure to remember or safely store your secret PIN/passphrase! Files encrypted with AES-256-GCM cannot be recovered without the original key.

---

## 📂 Project Structure

```
Swarmui-Image-Encriptor/
└── ImageEncryptor/
    ├── Assets/
    │   ├── image_encryptor.css  # UI styling for sidebar tab & keypad
    │   └── image_encryptor.js   # Client-side decryptor & interactive logic
    ├── ImageEncryptor.csproj    # C# extension project reference
    └── ImageEncryptorExtension.cs # C# backend extension hooks & AES-GCM encryption logic
```

---

## 🛡️ Security Considerations

- **Authenticated Encryption**: Uses AES-GCM to prevent silent payload modification or corruption.
- **Key Isolation**: Each file uses a unique random salt and nonce, preventing rainbow table or replay attacks.
- **In-Memory Safety**: Passphrases are processed on-demand and not stored in plaintext on disk.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

