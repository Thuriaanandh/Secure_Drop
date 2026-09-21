# SecureDrop — Security Verification & Testing Guide

**Tagline:** *Private files. Controlled access.*

This guide provides step-by-step test procedures for demonstrating every security control in SecureDrop during evaluations, audits, and cybersecurity/product-security interviews.

---

## 1. Prerequisites & Environment Setup

### 1.1 Start the SecureDrop Backend Server
Open a terminal in `backend/`:
```bash
cd backend
npm install
npm start
```
The server will start on `http://0.0.0.0:3000`:
- Android Emulator access: `http://10.0.2.2:3000`
- Physical Android Device access: `http://<YOUR_COMPUTER_LAN_IP>:3000` (e.g. `http://192.168.1.15:3000`)
- Local Machine access: `http://localhost:3000`

### 1.2 Run Automated Backend Security Test Suite
Verify backend security controls independently:
```bash
node test.js
```
Expected output:
```
======================================================
TEST SUMMARY: 15 PASSED, 0 FAILED
======================================================
```

---

## 2. Interactive In-App Security Demonstration Console (Fastest Demo)

SecureDrop includes a built-in interactive **Security Verification Console** available in Debug / Test Mode:

1. Launch SecureDrop.
2. On the Home Dashboard, tap the yellow **"Demo"** button in the top right.
3. Tap **"Run All"** or execute tests individually:
   - **TEST 1: Client-Side AES-256-GCM Encryption** (Validates 256-bit AES key, 12-byte IV, 16-byte tag, ciphertext != plaintext, and exact decryption).
   - **TEST 2: Cryptographic Tamper & Integrity Rejection** (Flips 1 bit in ciphertext; verifies SHA-256 mismatch and `AEADBadTagException` rejection).
   - **TEST 3: Expiring Link Rejection** (Creates 1-second share, waits 1.5s, verifies HTTP 410 Gone).
   - **TEST 4: One-Time Download Enforcement** (1st download -> HTTP 200 OK; 2nd download -> HTTP 410 Blocked).
   - **TEST 5: Instant Share Revocation** (Sender revokes share; recipient is immediately blocked with HTTP 403 Access Revoked).
   - **TEST 6: Screenshot Protection (FLAG_SECURE)** (Verifies window manager flag `0x2000` is active).
   - **TEST 7: Biometric Authentication Gate** (Verifies `BiometricManager` and hardware biometric/PIN gate).
   - **TEST 8: IDOR Object-Level Authorization Defense** (Attacker Mallory attempting to query Alice's file receives HTTP 403 Forbidden).

---

## 3. Manual Step-by-Step Security Test Cases

### Test Case 1: End-to-End Client-Side Encryption
- **Goal:** Prove the server NEVER receives the plaintext file.
- **Procedure:**
  1. Log in as Alice.
  2. Tap **"Secure Send"** and select a document (e.g., `Financial_Report.pdf`).
  3. Inspect the cryptographic audit block: shows precomputed SHA-256 hash and AES-256-GCM cipher parameters.
  4. Tap **"Encrypt & Upload"**.
  5. Check `backend/data/encrypted_uploads/`: inspect the uploaded file in a hex viewer or text editor.
- **Observed Result:** The file on disk is an encrypted binary blob with non-deterministic ciphertext. Server logs confirm only encrypted bytes and metadata were received.

### Test Case 2: One-Time Download Enforcement
- **Goal:** Verify that a one-time link self-destructs after the first successful download.
- **Procedure:**
  1. On Device A (or session 1), tap **"Secure Send"** -> select a file -> tap **"Encrypt & Upload"**.
  2. On the **Share Access Controls** screen, ensure **"One-Time Download"** is toggled **ON**.
  3. Tap **"Create Secure Share"**. Copy the generated composite share code.
  4. On Device B (or in app: **"Receive Share"**), paste the share code.
  5. Tap **"Verify & Open Share"** -> tap **"Authenticate & Download"**.
  6. **Download 1:** File downloads and decrypts successfully with status: `✓ INTEGRITY VERIFIED & DECRYPTED`.
  7. Now attempt a **second download**: Go back to **"Receive Share"**, paste the same code again, and tap **"Verify & Open Share"**.
- **Expected Result:**
  - Access is permanently blocked.
  - UI displays: `⚠️ Share Link Inactive: This secure link has already been used. One-time download consumed.`
  - Backend returns `HTTP 410 Gone`.

### Test Case 3: Ephemeral Expiring Links (30-Second Test Mode)
- **Goal:** Prove access terminates automatically when the expiration timestamp elapses.
- **Procedure:**
  1. Upload a file.
  2. On **Share Access Controls**, select **"30 Seconds (Test/Demo Mode)"** from the expiration dropdown.
  3. Tap **"Create Secure Share"** and copy the code.
  4. Wait 35 seconds.
  5. Navigate to **"Receive Share"**, paste the share code, and tap **"Verify & Open Share"**.
- **Expected Result:**
  - Lookup fails immediately with: `⚠️ Share Link Inactive: Share expired: This secure link has expired and is no longer available.`
  - Backend returns `HTTP 410 Gone`.

### Test Case 4: Instant Share Revocation
- **Goal:** Demonstrate real-time sender revocation.
- **Procedure:**
  1. Create a share with 24-hour expiration and multiple downloads. Copy the code.
  2. Test on Device B: Verify the share opens and downloads successfully.
  3. On Device A (Sender): Navigate to **"Vault & Shares"** -> select **"Active Shares"** tab.
  4. Find the share and tap the red **"Revoke"** button. Confirm in the dialog.
  5. Status badge changes to red `REVOKED`.
  6. On Device B: Try to download using the same link or code.
- **Expected Result:**
  - Device B receives: `⛔ Access Revoked: The sender has revoked access to this file.`
  - Server returns `HTTP 403 Forbidden`.
  - Security audit log records `DOWNLOAD_BLOCKED (reason: revoked)`.

### Test Case 5: Passcode Protection & Rate Limiting
- **Goal:** Prevent unauthorized downloads and defend against brute-force passcode guessing.
- **Procedure:**
  1. Create a share with **"Passcode Protection"** turned **ON** and passcode set to `Shield789`.
  2. Copy the share code.
  3. Open **"Receive Share"** and paste the code.
  4. Enter wrong passcode `000000` and tap **"Authenticate & Download"**.
  5. Repeat with incorrect passcodes 5 times.
- **Expected Result:**
  - Single incorrect passcode returns: `⛔ Incorrect Passcode. Access denied.` (HTTP 401).
  - After 5 failed attempts within 15 minutes, rate limiter triggers: `Too many failed passcode attempts. Locked for 900 seconds.` (HTTP 429).
  - Entering correct passcode `Shield789` grants access and resets attempts.

### Test Case 6: Cryptographic Payload Integrity Verification
- **Goal:** Prove tampered files are blocked and zeroized before opening.
- **Procedure:**
  1. Execute Test 2 in the **Security Demo Console** or tamper a `.enc` file in `backend/data/encrypted_uploads/`.
- **Expected Result:**
  - Recipient computes SHA-256 of downloaded ciphertext.
  - Computed SHA-256 fails comparison with the sender's recorded hash.
  - Decryption with AES-GCM tag verification throws `AEADBadTagException`.
  - Download is completely blocked; UI displays: `⚠ Integrity verification failed. Payload does not match cryptographic hash. Download blocked.`
  - Audit log records `INTEGRITY_FAILURE (Severity: CRITICAL)`.

### Test Case 7: FLAG_SECURE Screenshot Protection
- **Goal:** Prevent screen captures of sensitive documents.
- **Procedure:**
  1. Ensure **"Prevent Screenshots"** is enabled in Settings.
  2. Open any sensitive screen: **File Details**, **Download Verification**, or **Share Created**.
  3. Attempt taking a device screenshot (Power + Volume Down) or screen recording.
- **Expected Result:**
  - Android OS displays: `Can't take screenshot due to security policy.`
  - App window appears completely black in Android Recent Apps task switcher.
  - On Android 14+, in-app warning toast appears: `⚠️ Security Alert: Screenshot attempt detected on secure screen.` and logs `SCREENSHOT_DETECTED`.

### Test Case 8: IDOR (Insecure Direct Object Reference) Attack
- **Goal:** Prove User B cannot read User A's file by guessing `file_id`.
- **Procedure:**
  1. User A uploads file ID `9aebf5af5fdc30c3a99587b9077450ce`.
  2. Attacker User B logs in and issues `GET /api/files/9aebf5af5fdc30c3a99587b9077450ce`.
- **Expected Result:**
  - Backend strictly compares `file.owner_id === user.id`.
  - Returns `403 Forbidden`: `Access denied: You are not authorized to view or access this file`.
  - Audit log records: `UNAUTHORIZED_ACCESS_ATTEMPT (Severity: CRITICAL)`.

---

## 4. Two-Device Real-World Workflow

1. **Sender Device A:**
   - Registers user `alice_ciso@corporate.net`.
   - Selects confidential PDF -> AES-GCM Encrypts -> Sets 1-hour expiry + One-Time Download.
   - Generates share code.
2. **Recipient Device B:**
   - Enters share code.
   - Verifies fingerprint / biometric prompt.
   - Downloads encrypted payload -> SHA-256 Integrity Verified -> AES-GCM Decrypts.
   - Saves or views file.
3. **Verification on Device A:**
   - Navigates to **"Security Audit Trail"**.
   - Observes live timeline entries:
     - `SHARE_CREATED`
     - `SHARE_OPENED (Device B)`
     - `DOWNLOAD_COMPLETED (One-Time Link Consumed)`
