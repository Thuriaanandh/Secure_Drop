# SECUREDROP
### *Private files. Controlled access.*

SecureDrop is an enterprise-grade cybersecurity mobile application and backend engineered for zero-knowledge, end-to-end encrypted (E2EE) document transfer with cryptographic access controls. Built natively using Java, XML layouts, Android Keystore, BiometricPrompt, and a Node.js Express backend.

---

## 1. Key Application Security Features

| Security Control | Implementation Mechanism | Purpose & Threat Mitigation |
| :--- | :--- | :--- |
| **Client-Side E2E Encryption** | AES-256-GCM (`AES/GCM/NoPadding`) with unique 12-byte IV and 128-bit tag per file | Confidentially protects documents before leaving device; server stores 0 plaintext |
| **Cryptographic Key Protection** | Hardware/software `AndroidKeyStore` master key wrapping | Protects persistent file keys from filesystem dumping and extraction |
| **Zero-Knowledge Key Delivery** | Key embedded in URL fragment (`#key`) | Key is never transmitted across the network or stored in backend databases |
| **File Integrity Verification** | SHA-256 cryptographic digest computation | Blocks tampered or corrupted files prior to decryption |
| **Ephemeral Expiring Links** | Server-enforced timestamp verification (30s, 1m, 1h, 24h, 7d) | Auto-terminates link accessibility upon expiration |
| **One-Time Self-Destruct Links** | Atomic SQL update with race-condition defense | Invalidates download authorization immediately after 1st successful download |
| **Instant Share Revocation** | Real-time sender revocation toggle | Immediately terminates recipient access (HTTP 403) |
| **Passcode Protection & Rate Limiting**| Salted bcrypt hash + 15-minute lockout after 5 failed attempts | Defends against brute-force and unauthorized link discovery |
| **Biometric Decryption Gate** | `androidx.biometric.BiometricPrompt` & `BiometricManager` | Mandates physical biometric/device credential verification before decryption |
| **Screenshot & Record Protection** | `WindowManager.LayoutParams.FLAG_SECURE` + Android 14+ `ScreenCaptureCallback` | Prevents screen captures, screen sharing, and recent-app thumbnails |
| **IDOR Protection** | Strict object-level ownership checks (`owner_id === user.id`) | Blocks unauthorized cross-tenant file viewing and downloads |
| **Security Audit Trail** | Tamper-evident logging stored locally in SQLite and server database | Complete visibility into upload, share, download, and attack events |
| **Ephemeral Memory Management** | `Arrays.fill(buffer, (byte) 0)` memory wiping | Eliminates sensitive plaintext remnants in volatile heap memory |
| **Interactive Security Demo Console** | Built-in 8-test verification runner | Interactive live test suite for interviews and technical evaluation |

---

## 2. Technology Stack

- **Client Platform:** Android (Native Java, XML Layouts, Material Design Components)
- **Minimum SDK:** API 26 (Android 8.0 Oreo)
- **Compile SDK:** API 36 (Android 15+)
- **Security & Cryptography:**
  - `javax.crypto.Cipher` (AES-256-GCM)
  - `java.security.KeyStore` (`AndroidKeyStore`)
  - `java.security.MessageDigest` (SHA-256)
  - `java.security.SecureRandom`
  - `androidx.biometric:biometric:1.1.0`
  - Android Storage Access Framework (SAF)
- **Local Persistence:** Android `SQLiteOpenHelper`
- **Backend Architecture:**
  - Node.js 24 + Express
  - Native SQLite (`node:sqlite` / SQLite3)
  - Password Hashing: `bcryptjs` (12 rounds)
  - Sessions: Stateless JWT with 7-day expiration
  - Upload Handling: `multer` with binary streaming

---

## 3. Project Structure

```
project/
├── app/                                  # Android Client Application
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/securedrop/
│   │   │   │   ├── crypto/
│   │   │   │   │   └── CryptoManager.java               # AES-GCM, SHA-256, Keystore wrapping
│   │   │   │   ├── security/
│   │   │   │   │   ├── BiometricHelper.java             # BiometricPrompt integration
│   │   │   │   │   ├── ScreenshotProtectionHelper.java  # FLAG_SECURE & Android 14 callbacks
│   │   │   │   │   ├── SecurityScoreCalculator.java     # Local posture calculation (0-100)
│   │   │   │   │   └── AuditLogger.java                 # Unified audit dispatch
│   │   │   │   ├── data/
│   │   │   │   │   ├── db/SecureDropDatabaseHelper.java # Local SQLite storage
│   │   │   │   │   ├── pref/SecurityPreferences.java    # App security settings & sessions
│   │   │   │   │   └── model/                          # User, FileItem, ShareItem, LogItem
│   │   │   │   ├── network/
│   │   │   │   │   └── ApiClient.java                   # TLS HTTP client with auth & streaming
│   │   │   │   └── ui/
│   │   │   │       ├── auth/                            # Splash, Onboarding, Auth, BiometricLock
│   │   │   │       ├── main/                            # Home Dashboard (MainActivity)
│   │   │   │       ├── file/                            # Upload, ShareSettings, ShareCreated, MyFiles, FileDetails
│   │   │   │       ├── receive/                         # IncomingFile, DownloadVerification
│   │   │   │       ├── audit/                           # AccessLogsActivity (Security Timeline)
│   │   │   │       └── security/                        # SecurityCenter, Settings, SecurityDemoActivity
│   │   │   └── res/
│   │   │       ├── drawable/                            # Custom cyber themes, adaptive vectors
│   │   │       ├── layout/                              # 16 clean XML layout screens
│   │   │       ├── values/                              # Cybersecurity color palette, themes, strings
│   │   │       └── xml/network_security_config.xml      # TLS & localhost development config
│   │   └── test/java/com/securedrop/
│   │       └── CryptoManagerTest.java                   # Cryptographic unit test suite
│   └── build.gradle.kts
├── backend/                              # SecureDrop Backend Server
│   ├── server.js                         # Express server with security endpoints
│   ├── database.js                       # SQLite database & table initialization
│   ├── test.js                           # Automated backend security test suite
│   ├── package.json
│   └── data/                             # SQLite DB & encrypted upload storage
├── SECURITY_ARCHITECTURE.md              # Threat Model, STRIDE, Trust Boundaries
├── TESTING_GUIDE.md                      # Step-by-step test instructions
└── README.md
```

---

## 4. Setup & Running Instructions

### 4.1 Backend Setup
1. Open a terminal in the `backend/` directory:
   ```bash
   cd backend
   npm install
   npm start
   ```
2. The server binds to `0.0.0.0:3000`.

### 4.2 Android Studio / Gradle Setup
1. Open `C:\Users\anand\OneDrive\Documents\Android development\project` in **Android Studio**.
2. Android Studio will automatically recognize the project and sync Gradle.
3. Select an emulator or physical device running Android 8.0+ (API 26 to 36).
4. Click **Run 'app'** (`Shift + F10`) to build and launch SecureDrop.

### 4.3 Network Configuration (Emulator vs Physical Devices)
- **Standard Android Emulator:** The default server URL is pre-configured to `http://10.0.2.2:3000`. No changes needed!
- **Physical Android Device (LAN):**
  1. Find your computer's local IP (e.g. `ipconfig` -> `192.168.1.50`).
  2. In SecureDrop, open **Settings** (or tap the gear icon on Auth screen).
  3. Change the Backend Server URL to `http://192.168.1.50:3000` and tap **Save**.

---

## 5. Two-Device Real-World Testing Workflow

1. **Device A (Sender - Alice):**
   - Register account: `alice@cyber.org`.
   - Tap **"Secure Send"** -> select a PDF or image.
   - Observe local AES-256-GCM encryption & SHA-256 calculation.
   - Set expiration to **10 minutes**, toggle **One-Time Download**, set passcode `Safe123`.
   - Tap **"Create Secure Share"** -> tap **"Copy Secure Code"**.
2. **Device B (Recipient - Bob):**
   - Open SecureDrop -> tap **"Receive Share"**.
   - Paste the code -> tap **"Verify & Open Share"**.
   - Enter passcode `Safe123`.
   - Tap **"Authenticate & Download"** -> verify fingerprint / biometric prompt.
   - App downloads encrypted payload, performs SHA-256 integrity check, and decrypts locally using AES-GCM.
3. **Verify Security Enforcement on Device B:**
   - Attempt to download using the same code a second time:
     `⚠️ This secure link has already been used. One-time download consumed.`
4. **Verify Audit Trail on Device A:**
   - On Device A, open **"Audit Trail"**.
   - Review immutable timestamps: `FILE_UPLOADED`, `SHARE_CREATED`, `SHARE_OPENED`, `DOWNLOAD_COMPLETED`.

---

## 6. How to Demonstrate in a Cybersecurity Interview

1. **Highlight Threat Modeling:** Walk through `SECURITY_ARCHITECTURE.md` explaining the STRIDE model, zero-knowledge principles, and why the server never sees plaintext.
2. **Launch the Security Demo Console:** Navigate to the in-app **"Demo"** screen and run the 8 interactive tests showing real-time PASS/FAIL status.
3. **Demonstrate Tamper Detection:** Explain how AES-256-GCM authentication tags and SHA-256 hashes detect single-bit corruption and block unauthorized execution.
4. **Demonstrate IDOR Resistance:** Show how object-level checks prevent an authenticated attacker from reading other users' files.
5. **Show Keystore Protection:** Explain how per-file keys are wrapped using a hardware-backed master key in `AndroidKeyStore`.
