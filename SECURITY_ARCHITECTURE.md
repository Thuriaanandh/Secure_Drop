# SecureDrop — Security Architecture & Threat Model

**Tagline:** *Private files. Controlled access.*

---

## 1. System Overview

SecureDrop is an enterprise-grade mobile application and backend designed for zero-knowledge, end-to-end encrypted (E2EE) file sharing with granular, ephemeral access controls. The architecture assumes a hostile network and an untrusted backend storage server, enforcing cryptographic guarantees directly on client endpoints.

---

## 2. Security Architecture Diagram

```
+-------------------------------------------------------------------------------+
|                             SENDER DEVICE (Android)                           |
|                                                                               |
|  [Plaintext File]                                                             |
|         │                                                                     |
|         ▼                                                                     |
|  [SHA-256 Hash Computation]                                                   |
|         │                                                                     |
|         ▼                                                                     |
|  [Generate 256-bit AES Key via SecureRandom]                                  |
|         │                                                                     |
|         ├──► Local Storage: [Key Wrapped via Android Keystore Master Key]     |
|         │                                                                     |
|         ▼                                                                     |
|  [AES-256-GCM Local Encryption] ──► Produces: Ciphertext + 12B IV + 16B Tag   |
|         │                                                                     |
|         ▼ (Ciphertext + Metadata only - PLAINTEXT NEVER SENT)                 |
+─────────┼─────────────────────────────────────────────────────────────────────+
          │  HTTPS / TLS 1.3
          ▼
+────────────────────────────────────────────────────────────────---------------+
|                           SECUREDROP BACKEND SERVER                           |
|                                                                               |
|  ├── Authentication & Session Management (Salted bcrypt + JWT)                |
|  ├── Encrypted Blob Storage (.enc files only, 0 knowledge of plaintext)       |
|  ├── Share Management (Stores SHA-256(token) - Raw token NEVER in DB)         |
|  ├── Strict Object-Level Authorization (IDOR Defense)                         |
|  ├── Ephemeral Expiration Enforcement (30s, 1m, 1h, 24h, 7d)                  |
|  ├── Atomic One-Time Download Enforcement (Race-condition safe)               |
|  ├── Passcode Hashing & Failed Attempt Rate Limiting                          |
|  └── Immutable Security Audit Logging                                         |
+─────────┬─────────────────────────────────────────────────────────────────────+
          │  HTTPS / TLS 1.3 (Ciphertext blob + verification headers)
          ▼
+────────────────────────────────────────────────────────────────---------------+
|                           RECIPIENT DEVICE (Android)                          |
|                                                                               |
|  Composite Share Code: [Token] # [AES-Key]                                    |
|         │                        │                                            |
|         ├────────────────────────┼─ (Token sent to Server; Key kept local!)   |
|         │                        │                                            |
|  [Biometric / Device Authentication Gate]                                     |
|         │                                                                     |
|         ▼                                                                     |
|  [Download Encrypted Blob]                                                    |
|         │                                                                     |
|         ▼                                                                     |
|  [Verify SHA-256 Payload Hash] ──► Mismatch? ──► BLOCK ACCESS & ZEROIZE       |
|         │ Valid                                                               |
|         ▼                                                                     |
|  [AES-256-GCM Local Decryption using in-memory Key]                           |
|         │                                                                     |
|         ▼                                                                     |
|  [Protected Viewer Window with FLAG_SECURE & Android 14 Capture Auditing]     |
|         │                                                                     |
|         ▼                                                                     |
|  [Ephemeral Memory Zeroization on Dismiss]                                    |
+-------------------------------------------------------------------------------+
```

---

## 3. Threat Model (STRIDE Framework)

### 3.1 Assets
1. **User Plaintext Documents**: Sensitive PDFs, DOCX, financial reports, credentials, keys.
2. **Cryptographic Symmetric Keys**: 256-bit AES file encryption keys.
3. **Hardware Master Keys**: AES-256 keys generated inside the Android KeyStore / StrongBox.
4. **Share Tokens**: Cryptographically random 256-bit entropy tokens granting authorized download.
5. **Passcodes**: Secret phrases configured by senders.
6. **Audit Logs**: Forensically relevant security event records.

### 3.2 Threat Actors
- **Network Adversary (MITM)**: Intercepts, modifies, or replays traffic between client and server.
- **Compromised Backend Operator / Malicious Server**: Inspects database dumps, reads stored file payloads, alters metadata.
- **Untrusted / Unauthorized Users (IDOR)**: Tries guessing or enumerating file IDs or share IDs.
- **Malicious Recipient**: Attempts to re-download expired or one-time shares; attempts unauthorized screenshots.
- **Device Thief**: Physical access to an unlocked or locked device.

### 3.3 Threats & Mitigations Matrix

| Threat | STRIDE Category | Attack Mechanism | SecureDrop Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Server Compromise / Data Breach** | Information Disclosure | Attacker dumps backend database and disk storage. | **Zero-Knowledge Architecture:** Client-side AES-256-GCM. Plaintext is never sent to the server. Server stores only `.enc` encrypted files. Decryption keys are never stored on the server. |
| **Token Guessing / Enumeration** | Spoofing / Tampering | Attacker tries brute-forcing share IDs or incrementing numeric IDs. | **256-bit Entropy Tokens:** Shares use `crypto.randomBytes(32)` (2^256 combinations). Database stores only `SHA-256(token)`. Numeric IDs are never exposed in URLs. |
| **Insecure Direct Object Reference (IDOR)** | Elevation of Privilege | User B queries `GET /api/files/:userA_file_id`. | **Strict Object-Level Ownership Checks:** Backend verifies `file.owner_id === user.id` on every operation. Unauthorized queries return `403 Forbidden` and log a `UNAUTHORIZED_ACCESS_ATTEMPT` critical security event. |
| **Link Replay / Stale Access** | Information Disclosure | Recipient attempts access after authorized time window. | **Server-Enforced Expiry:** Backend calculates `Date.now() < expires_at` on every lookup and download request. Expired links return `410 Gone`. |
| **Multi-Fetch of Single-Use Files** | Information Disclosure | Link shared in group or leaked; multiple parties attempt download. | **Atomic One-Time Invalidation:** Backend executes atomic SQL `UPDATE shares SET download_count = download_count + 1 WHERE id = ? AND download_count = 0`. First download succeeds; subsequent attempts return `410 Gone`. |
| **Revocation Bypass** | Elevation of Privilege | Sender revokes share, but recipient attempts cached link. | **Immediate State Invalidation:** Server sets `revoked = 1`. All subsequent lookups and downloads immediately fail with `403 Access Revoked`. |
| **Network Payload Tampering** | Tampering | Active MITM modifies encrypted ciphertext in transit. | **Dual Authenticated Integrity:** Client precomputes SHA-256 hash. AES-GCM verifies 128-bit authentication tag. Tampered bytes trigger `AEADBadTagException` and SHA-256 failure; download is immediately blocked and zeroized. |
| **Passcode Brute-Forcing** | Elevation of Privilege | Attacker repeatedly guesses 4-8 character share passcodes. | **Rate-Limiting & bcrypt:** Passcodes hashed using salted bcrypt. Backend locks token for 15 minutes after 5 failed attempts, returning `429 Too Many Requests`. |
| **Unauthorized Physical Device Access** | Elevation of Privilege | Thief picks up unlocked device or opens app. | **Biometric Gate:** App requires `BiometricPrompt` on resume. Decryption requires explicit biometric/device credential verification. Master keys protected by `AndroidKeyStore`. |
| **Shoulder Surfing & Screen Capture** | Information Disclosure | Malicious app takes background screenshots or user records screen. | **FLAG_SECURE:** Window manager prevents screenshots and hides app thumbnail in Android recent tasks switcher. Android 14+ `ScreenCaptureCallback` alerts and audits attempts. |

---

## 4. Cryptographic Key Lifecycle

1. **Generation:**
   - Per-File Symmetric Key: Generated using `KeyGenerator.getInstance("AES")` initialized to 256 bits with `SecureRandom`.
   - Android Keystore Master Key: Generated inside `AndroidKeyStore` using `KeyGenParameterSpec` with `KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT` and `KeyProperties.BLOCK_MODE_GCM`.
2. **Protection:**
   - On the device, the file key is wrapped using AES-GCM under the Keystore Master Key before storing metadata in the local SQLite database.
   - For sharing, the file key is embedded in the URL fragment (`#<key>`). In HTTP standards, URL fragments are never transmitted to the server.
3. **Use:**
   - Authenticated encryption: `AES/GCM/NoPadding` with a unique 96-bit (12-byte) random IV per encryption.
   - GCM tag length: 128 bits.
4. **Destruction & Memory Zeroization:**
   - Plaintext buffers and decrypted byte arrays are explicitly overwritten using `Arrays.fill(buffer, (byte) 0)` immediately after use or when viewing activities are destroyed.

---

## 5. Residual Risks & Operational Considerations

1. **Rooted Devices / Hooking Frameworks:**
   - A rooted device with Frida or Xposed could hook Java memory or JVM cryptographic APIs. Mitigation: Android KeyStore hardware backing (TEE / StrongBox) keeps master keys isolated outside Android OS memory space.
2. **Compromised Endpoints:**
   - If either the sender's or recipient's operating system is fully compromised by a kernel-level keylogger or spyware, plaintext can be intercepted before encryption or after decryption.
