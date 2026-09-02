/**
 * Helper class for Image Encryptor Extension in SwarmUI.
 * Manages the Left Sidebar security tab, real-time AES-256 encryption status,
 * enable/disable toggle, parameter synchronization, and on-the-fly image decryption.
 */
class ImageEncryptorHelper {

    constructor() {
        this.isEnabled = true;
        this.currentCode = '';
        this.isCodeVisible = false;
        this.magicHeader = [0x53, 0x57, 0x41, 0x52, 0x4D, 0x45, 0x4E, 0x43]; // 'SWARMENC'
        this.headerSize = 53;
        this.isInitialized = false;
    }

    /**
     * Initializes the Image Encryptor UI and event listeners once the DOM / session is ready.
     */
    init() {
        if (this.isInitialized) {
            return;
        }
        this.isInitialized = true;

        this.injectSidebarTab();
        this.hookGenerationInputs();
        this.loadSavedState();
    }

    /**
     * Injects the '🔒 Encryptor' sub-tab into the Left Sidebar.
     */
    injectSidebarTab() {
        let navCollection = document.getElementById('inputsidebartabcollection');
        let contentCollection = document.getElementById('inputsidebartab_content');

        if (!navCollection || !contentCollection) {
            setTimeout(() => {
                this.injectSidebarTab();
            }, 500);
            return;
        }

        // Avoid duplicate insertion
        if (document.getElementById('encryptortablink')) {
            return;
        }

        // Create nav item
        let navItem = document.createElement('li');
        navItem.className = 'nav-item';
        navItem.setAttribute('role', 'presentation');
        navItem.innerHTML = `<a class="nav-link translate" data-bs-toggle="tab" href="#Input-Sidebar-Encryptor-Tab" id="encryptortablink" role="tab"><span class="encryptor-icon">🔒</span> Encryptor</a>`;
        navCollection.appendChild(navItem);

        // Create tab content pane
        let tabPane = document.createElement('div');
        tabPane.className = 'tab-pane genpage-bottom-tab encryptor-tab-container';
        tabPane.id = 'Input-Sidebar-Encryptor-Tab';
        tabPane.setAttribute('role', 'tabpanel');

        tabPane.innerHTML = `
            <div class="encryptor-pane-inner">
                <!-- Main Toggle Switch Card -->
                <div class="encryptor-toggle-card">
                    <div class="encryptor-toggle-row">
                        <div class="form-check form-switch encryptor-switch-wrapper">
                            <input class="form-check-input encryptor-toggle-switch" type="checkbox" id="encryptor_enable_toggle" checked />
                            <label class="form-check-label encryptor-toggle-title" for="encryptor_enable_toggle">Enable Disk Encryption</label>
                        </div>
                    </div>
                </div>

                <!-- Status Card -->
                <div class="encryptor-status-card" id="encryptor_status_card">
                    <div class="encryptor-status-header">
                        <span class="encryptor-status-dot" id="encryptor_status_dot"></span>
                        <span class="encryptor-status-title" id="encryptor_status_title">Encryption Inactive</span>
                    </div>
                    <div class="encryptor-status-desc" id="encryptor_status_desc">
                        Enter a passcode or PIN to automatically encrypt generated images with AES-256-GCM on disk.
                    </div>
                </div>

                <!-- Passcode Input Section -->
                <div class="encryptor-input-section">
                    <label class="encryptor-label" for="encryptor_code_input">Secret Passcode / PIN:</label>
                    <div class="encryptor-input-row">
                        <input type="password" id="encryptor_code_input" class="auto-text encryptor-code-field" placeholder="Enter secret code or PIN..." autocomplete="off" />
                        <button type="button" class="basic-button encryptor-action-btn" id="encryptor_toggle_vis_btn" title="Show / Hide Code">&#128065;</button>
                        <button type="button" class="basic-button encryptor-action-btn encryptor-clear-btn" id="encryptor_clear_code_btn" title="Clear Code">&#10005;</button>
                    </div>
                </div>

                <!-- Quick Keypad Section -->
                <div class="encryptor-keypad-card">
                    <div class="encryptor-keypad-title">Quick PIN Keypad</div>
                    <div class="encryptor-keypad-grid">
                        <button type="button" class="basic-button encryptor-key-btn" data-key="1">1</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="2">2</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="3">3</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="4">4</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="5">5</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="6">6</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="7">7</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="8">8</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="9">9</button>
                        <button type="button" class="basic-button encryptor-key-btn encryptor-key-action" data-key="clear">C</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="0">0</button>
                        <button type="button" class="basic-button encryptor-key-btn" data-key="back">&#9003;</button>
                    </div>
                </div>

                <!-- Tools Section -->
                <div class="encryptor-quick-tools">
                    <button type="button" class="basic-button encryptor-tool-btn" id="encryptor_random_pin_btn">&#127922; Generate Random PIN</button>
                </div>

                <!-- File Decryptor Dropzone Section -->
                <div class="encryptor-dropzone-section">
                    <div class="encryptor-dropzone-title">File Decryptor</div>
                    <div class="encryptor-dropzone" id="encryptor_file_dropzone">
                        <div class="encryptor-dropzone-icon">&#128194;</div>
                        <div class="encryptor-dropzone-text">Drag & drop an encrypted image (.png, .enc, .webp) here to decrypt</div>
                        <input type="file" id="encryptor_file_input" style="display:none;" accept="image/*,.enc,.png,.jpg,.jpeg,.webp" />
                    </div>
                    <div class="encryptor-preview-box" id="encryptor_preview_box" style="display:none;">
                        <img id="encryptor_preview_img" class="encryptor-preview-image" alt="Decrypted Preview" />
                        <div class="encryptor-preview-actions">
                            <a id="encryptor_download_decrypted_link" class="basic-button encryptor-download-btn" download="decrypted_image.png">Download Decrypted Image</a>
                        </div>
                    </div>
                </div>
            </div>
        `;

        contentCollection.appendChild(tabPane);

        let linkElem = document.getElementById('encryptortablink');
        if (linkElem) {
            linkElem.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                let parentNav = linkElem.closest('.swarm-gen-tab-subnav') || document.getElementById('inputsidebartabcollection');
                if (parentNav) {
                    for (let navLink of parentNav.querySelectorAll('.nav-link')) {
                        navLink.classList.remove('active');
                        navLink.setAttribute('aria-selected', 'false');
                    }
                }

                let parentContent = tabPane.closest('.tab-content') || document.getElementById('inputsidebartab_content');
                if (parentContent) {
                    for (let pane of parentContent.querySelectorAll('.tab-pane')) {
                        pane.classList.remove('active');
                        pane.classList.remove('show');
                    }
                }

                linkElem.classList.add('active');
                linkElem.setAttribute('aria-selected', 'true');
                tabPane.classList.add('active');
                tabPane.classList.add('show');

                if (window.genTabLayout && typeof window.genTabLayout.reapplyPositions == 'function') {
                    window.genTabLayout.reapplyPositions();
                }
            });
        }

        this.bindEvents();
    }

    /**
     * Binds UI events for toggle switch, inputs, buttons, and file dropzone.
     */
    bindEvents() {
        let toggleSwitch = document.getElementById('encryptor_enable_toggle');
        let codeInput = document.getElementById('encryptor_code_input');
        let toggleVisBtn = document.getElementById('encryptor_toggle_vis_btn');
        let clearBtn = document.getElementById('encryptor_clear_code_btn');
        let randomBtn = document.getElementById('encryptor_random_pin_btn');
        let dropzone = document.getElementById('encryptor_file_dropzone');
        let fileInput = document.getElementById('encryptor_file_input');

        if (toggleSwitch) {
            toggleSwitch.addEventListener('change', () => {
                this.setEnabled(toggleSwitch.checked);
            });
        }

        if (codeInput) {
            codeInput.addEventListener('input', () => {
                this.setCode(codeInput.value);
            });
        }

        if (toggleVisBtn) {
            toggleVisBtn.addEventListener('click', () => {
                this.isCodeVisible = !this.isCodeVisible;
                if (codeInput) {
                    codeInput.type = this.isCodeVisible ? 'text' : 'password';
                }
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.setCode('');
            });
        }

        if (randomBtn) {
            randomBtn.addEventListener('click', () => {
                let randomPin = '';
                for (let i = 0; i < 8; i++) {
                    randomPin += Math.floor(Math.random() * 10);
                }
                this.setCode(randomPin);
                if (!this.isEnabled) {
                    this.setEnabled(true);
                }
            });
        }

        // Keypad buttons
        let keyBtns = document.querySelectorAll('.encryptor-key-btn');
        for (let btn of keyBtns) {
            btn.addEventListener('click', () => {
                let key = btn.dataset.key;
                if (!codeInput) {
                    return;
                }
                if (key == 'clear') {
                    this.setCode('');
                }
                else if (key == 'back') {
                    this.setCode(codeInput.value.slice(0, -1));
                }
                else {
                    this.setCode(codeInput.value + key);
                }
            });
        }

        // Dropzone events
        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => {
                fileInput.click();
            });

            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) {
                    this.processDroppedFile(e.target.files[0]);
                }
            });

            dropzone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropzone.classList.add('dragover');
            });

            dropzone.addEventListener('dragleave', () => {
                dropzone.classList.remove('dragover');
            });

            dropzone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropzone.classList.remove('dragover');
                if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
                    this.processDroppedFile(e.dataTransfer.files[0]);
                }
            });
        }
    }

    /**
     * Sets the enabled/disabled state of the encryptor.
     */
    setEnabled(enabled) {
        this.isEnabled = enabled;
        let toggleSwitch = document.getElementById('encryptor_enable_toggle');
        if (toggleSwitch && toggleSwitch.checked != this.isEnabled) {
            toggleSwitch.checked = this.isEnabled;
        }

        this.updateStatusBadge();
        this.syncStateWithServer();

        try {
            localStorage.setItem('swarm_encryptor_enabled', this.isEnabled ? 'true' : 'false');
        }
        catch (e) { }
    }

    /**
     * Sets the active encryption code, updates the UI and syncs with server.
     */
    setCode(newCode) {
        this.currentCode = (newCode || '').trim();
        let codeInput = document.getElementById('encryptor_code_input');
        if (codeInput && codeInput.value != this.currentCode) {
            codeInput.value = this.currentCode;
        }

        this.updateStatusBadge();
        this.syncParamWithGenInput();
        this.syncStateWithServer();

        try {
            if (this.currentCode) {
                sessionStorage.setItem('swarm_encryptor_code', this.currentCode);
                localStorage.setItem('swarm_encryptor_code', this.currentCode);
            }
            else {
                sessionStorage.removeItem('swarm_encryptor_code');
                localStorage.removeItem('swarm_encryptor_code');
            }
        }
        catch (e) { }
    }

    /**
     * Synchronizes state with the server via WebAPI.
     */
    syncStateWithServer() {
        genericRequest('ImageEncryptor_SetState', {
            enabled: this.isEnabled,
            code: this.currentCode
        }, (data) => {
            // State updated on server
        });
    }

    /**
     * Loads saved code and toggle state from storage.
     */
    loadSavedState() {
        try {
            let savedEnabled = localStorage.getItem('swarm_encryptor_enabled');
            if (savedEnabled !== null) {
                this.isEnabled = savedEnabled == 'true';
                let toggleSwitch = document.getElementById('encryptor_enable_toggle');
                if (toggleSwitch) {
                    toggleSwitch.checked = this.isEnabled;
                }
            }

            let savedCode = sessionStorage.getItem('swarm_encryptor_code') || localStorage.getItem('swarm_encryptor_code');
            if (savedCode) {
                this.setCode(savedCode);
            }
            else {
                this.updateStatusBadge();
                this.syncStateWithServer();
            }
        }
        catch (e) {
            this.updateStatusBadge();
        }
    }

    /**
     * Updates the status badge UI according to whether encryption is enabled and has a code.
     */
    updateStatusBadge() {
        let card = document.getElementById('encryptor_status_card');
        let dot = document.getElementById('encryptor_status_dot');
        let title = document.getElementById('encryptor_status_title');
        let desc = document.getElementById('encryptor_status_desc');

        if (!card || !dot || !title || !desc) {
            return;
        }

        if (!this.isEnabled) {
            card.className = 'encryptor-status-card disabled';
            dot.className = 'encryptor-status-dot disabled';
            title.innerText = '⚪ Encryption Disabled';
            desc.innerText = 'Encryption is switched off. Output images will be saved normally without encryption.';
        }
        else if (this.currentCode.length > 0) {
            card.className = 'encryptor-status-card active';
            dot.className = 'encryptor-status-dot active';
            title.innerText = '🟢 Encryption Active (AES-256)';
            desc.innerText = 'All newly generated output images will be instantly encrypted on disk with your code.';
        }
        else {
            card.className = 'encryptor-status-card waiting';
            dot.className = 'encryptor-status-dot waiting';
            title.innerText = '🟡 Enabled (Enter Code or PIN)';
            desc.innerText = 'Encryption is enabled, but waiting for a passcode or PIN to be entered.';
        }
    }

    /**
     * Synchronizes the code with the native SwarmUI parameter input.
     */
    syncParamWithGenInput() {
        let paramInput = document.getElementById('input_imageencryptioncode');
        if (paramInput) {
            paramInput.value = this.isEnabled ? this.currentCode : '';
            let toggle = document.getElementById('input_imageencryptioncode_toggle');
            if (toggle) {
                toggle.checked = this.isEnabled && this.currentCode.length > 0;
            }
        }
    }

    /**
     * Hooks into the SwarmUI generation input builder to attach the encryption code.
     */
    hookGenerationInputs() {
        if (typeof getGenInput == 'function') {
            let originalGetGenInput = getGenInput;
            let self = this;
            window.getGenInput = function() {
                let res = originalGetGenInput.apply(this, arguments);
                if (self.isEnabled && self.currentCode && self.currentCode.length > 0) {
                    res['imageencryptioncode'] = self.currentCode;
                }
                else {
                    delete res['imageencryptioncode'];
                }
                return res;
            };
        }
    }

    /**
     * Checks if a binary ArrayBuffer begins with the 'SWARMENC' magic header.
     */
    isBufferEncrypted(buffer) {
        if (!buffer || buffer.byteLength < this.headerSize) {
            return false;
        }
        let bytes = new Uint8Array(buffer);
        for (let i = 0; i < this.magicHeader.length; i++) {
            if (bytes[i] != this.magicHeader[i]) {
                return false;
            }
        }
        return bytes[8] == 0x01; // Version 1
    }

    /**
     * Derives an AES-GCM 256-bit CryptoKey using PBKDF2 with SHA-256.
     */
    async deriveKey(passphrase, salt) {
        let enc = new TextEncoder();
        let passKey = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(passphrase),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            passKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Decrypts an ArrayBuffer containing a SwarmEnc encrypted payload using Web Crypto API.
     */
    async decryptBuffer(buffer, passphrase) {
        if (!this.isBufferEncrypted(buffer)) {
            return buffer;
        }

        let bytes = new Uint8Array(buffer);
        let salt = bytes.slice(9, 25);
        let nonce = bytes.slice(25, 37);
        let tag = bytes.slice(37, 53);
        let ciphertext = bytes.slice(53);

        // WebCrypto AES-GCM expects ciphertext concatenated with the tag
        let combined = new Uint8Array(ciphertext.length + tag.length);
        combined.set(ciphertext, 0);
        combined.set(tag, ciphertext.length);

        let key = await this.deriveKey(passphrase, salt);

        return await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: nonce
            },
            key,
            combined
        );
    }

    /**
     * Handles dropping an encrypted file on the dropzone.
     */
    async processDroppedFile(file) {
        let code = this.currentCode;
        if (!code) {
            alert('Please enter your secret encryption passcode or PIN in the field above before decrypting this file.');
            return;
        }

        try {
            let buffer = await file.arrayBuffer();
            if (!this.isBufferEncrypted(buffer)) {
                let blob = new Blob([buffer], { type: file.type || 'image/png' });
                this.showDecryptedPreview(blob);
                return;
            }

            let decryptedBuffer = await this.decryptBuffer(buffer, code);
            let mime = 'image/png';
            let u8 = new Uint8Array(decryptedBuffer);
            if (u8.length > 3 && u8[0] == 0xFF && u8[1] == 0xD8 && u8[2] == 0xFF) {
                mime = 'image/jpeg';
            }
            else if (u8.length > 12 && u8[0] == 0x52 && u8[1] == 0x49 && u8[2] == 0x46 && u8[3] == 0x46) {
                mime = 'image/webp';
            }

            let blob = new Blob([decryptedBuffer], { type: mime });
            this.showDecryptedPreview(blob);
        }
        catch (err) {
            console.error('[ImageEncryptor] Decryption error:', err);
            alert('Decryption failed: Incorrect passcode / PIN or corrupted file.');
        }
    }

    /**
     * Displays the decrypted image in the preview box.
     */
    showDecryptedPreview(blob) {
        let previewBox = document.getElementById('encryptor_preview_box');
        let previewImg = document.getElementById('encryptor_preview_img');
        let downloadLink = document.getElementById('encryptor_download_decrypted_link');

        if (!previewBox || !previewImg || !downloadLink) {
            return;
        }

        let url = URL.createObjectURL(blob);
        previewImg.src = url;
        downloadLink.href = url;
        previewBox.style.display = 'block';
    }
}

let imageEncryptorHelper = new ImageEncryptorHelper();

// Initialize when session/page is ready
if (typeof sessionReadyCallbacks != 'undefined') {
    sessionReadyCallbacks.push(() => {
        imageEncryptorHelper.init();
    });
}
else {
    document.addEventListener('DOMContentLoaded', () => {
        imageEncryptorHelper.init();
    });
}
