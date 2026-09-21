const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Test suite for SecureDrop Backend Security Controls
const PORT = 3001;
process.env.PORT = PORT;
const app = require('./server');

function request(options, data = null, isMultipart = false) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        let parsed;
        try {
          parsed = JSON.parse(body);
        } catch (e) {
          parsed = body;
        }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);

    if (data) {
      if (Buffer.isBuffer(data) || typeof data === 'string') {
        req.write(data);
      } else {
        req.write(JSON.stringify(data));
      }
    }
    req.end();
  });
}

async function runTests() {
  console.log('\n======================================================');
  console.log('   SECUREDROP BACKEND AUTOMATED SECURITY TESTS');
  console.log('======================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ✗ FAIL: ${message}`);
      failed++;
    }
  }

  try {
    const runId = Date.now();
    const userA = 'alice_' + runId;
    const emailA = `alice_${runId}@securedrop.test`;
    const userB = 'mallory_' + runId;
    const emailB = `mallory_${runId}@securedrop.test`;

    // 1. Register User A
    console.log('[TEST 1] Registration and Password Security');
    const regResA = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      username: userA,
      email: emailA,
      password: 'SuperSecretPassword123!'
    });
    assert(regResA.status === 201 && regResA.body.token, 'User A registered with hashed password and token returned');
    const tokenA = regResA.body.token;

    // 2. Register User B (for IDOR attack tests)
    const regResB = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/auth/register',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      username: userB,
      email: emailB,
      password: 'AttackerPassword456!'
    });
    assert(regResB.status === 201 && regResB.body.token, 'User B registered for authorization testing');
    const tokenB = regResB.body.token;

    // 3. Login User A
    console.log('\n[TEST 2] Authentication and Session Management');
    const loginRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      identifier: userA,
      password: 'SuperSecretPassword123!'
    });
    assert(loginRes.status === 200 && loginRes.body.token, 'User A logged in successfully with valid credentials');

    // 4. Client-side simulated encrypted payload upload
    console.log('\n[TEST 3] Encrypted Payload Upload & Integrity Verification');
    const fakePlaintext = 'TOP SECRET APPLICATION SECURITY SPECIFICATION';
    const fakeKey = crypto.randomBytes(32); // AES-256 key
    const iv = crypto.randomBytes(12); // GCM IV
    const cipher = crypto.createCipheriv('aes-256-gcm', fakeKey, iv);
    let ciphertext = cipher.update(fakePlaintext, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();

    const sha256Encrypted = crypto.createHash('sha256').update(ciphertext).digest('hex');
    const sha256Plaintext = crypto.createHash('sha256').update(fakePlaintext, 'utf8').digest('hex');

    // Upload with multipart
    const boundary = '----WebKitFormBoundarySecureDropTest' + Date.now();
    let bodyBuffers = [];

    function addField(name, val) {
      bodyBuffers.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${val}\r\n`));
    }

    addField('original_name', 'spec_secret.pdf');
    addField('mime_type', 'application/pdf');
    addField('encrypted_size', ciphertext.length);
    addField('plaintext_size', Buffer.byteLength(fakePlaintext));
    addField('sha256_hash', sha256Encrypted);
    addField('plaintext_sha256', sha256Plaintext);
    addField('iv_hex', iv.toString('hex'));
    addField('auth_tag_hex', authTag.toString('hex'));

    // File part
    bodyBuffers.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="encrypted_file"; filename="spec_secret.enc"\r\nContent-Type: application/octet-stream\r\n\r\n`));
    bodyBuffers.push(ciphertext);
    bodyBuffers.push(Buffer.from(`\r\n--${boundary}--\r\n`));

    const fullPayload = Buffer.concat(bodyBuffers);

    const uploadRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/files/upload',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': fullPayload.length
      }
    }, fullPayload, true);

    assert(uploadRes.status === 201 && uploadRes.body.file.id, 'Encrypted file uploaded & server-side payload SHA-256 verified');
    const fileIdA = uploadRes.body.file.id;

    // 5. IDOR Object-Level Authorization Test: User B tries to view User A's file
    console.log('\n[TEST 4] Insecure Direct Object Reference (IDOR) Defense');
    const idorRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/files/${fileIdA}`,
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenB}` }
    });
    assert(idorRes.status === 403, 'Attacker User B denied access to User A file (HTTP 403 Forbidden)');

    // 6. Test Expiration Enforcement
    console.log('\n[TEST 5] Expiring Link Enforcement');
    // Create share with 1 second expiry
    const expireShareRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/shares',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': 'application/json'
      }
    }, {
      file_id: fileIdA,
      expires_in_seconds: 1, // 1 second!
      one_time: false
    });
    assert(expireShareRes.status === 201 && expireShareRes.body.share.token, 'Expiring share created (1 second expiry)');
    const expiringToken = expireShareRes.body.share.token;

    // Wait 1.5 seconds for expiration
    console.log('    Waiting 1500ms for expiration...');
    await new Promise(r => setTimeout(r, 1500));

    const expiredLookup = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/lookup/${expiringToken}`,
      method: 'GET'
    });
    assert(expiredLookup.status === 410, 'Access blocked after expiration timestamp (HTTP 410 Gone / Share Expired)');

    // 7. Test One-Time Download Enforcement
    console.log('\n[TEST 6] One-Time Download Enforcement');
    const oneTimeShareRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/shares',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': 'application/json'
      }
    }, {
      file_id: fileIdA,
      expires_in_seconds: 3600,
      one_time: true
    });
    const oneTimeToken = oneTimeShareRes.body.share.token;
    assert(oneTimeShareRes.status === 201 && oneTimeToken, 'One-time download share created');

    // First download: Should succeed
    const firstDl = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/download/${oneTimeToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {});
    assert(firstDl.status === 200, 'First download attempt succeeded (HTTP 200)');

    // Second download: MUST BE BLOCKED!
    const secondDl = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/download/${oneTimeToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {});
    assert(secondDl.status === 410, 'Second download attempt permanently blocked (HTTP 410 One-time consumed)');

    // 8. Test File Revocation
    console.log('\n[TEST 7] Instant Share Revocation');
    const revokeShareRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/shares',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': 'application/json'
      }
    }, {
      file_id: fileIdA,
      expires_in_seconds: 3600,
      one_time: false
    });
    const shareToRevokeId = revokeShareRes.body.share.id;
    const revokeToken = revokeShareRes.body.share.token;

    // Sender revokes
    const revokeAction = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/${shareToRevokeId}/revoke`,
      method: 'POST',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    assert(revokeAction.status === 200, 'Share revoked by sender');

    // Recipient tries to download
    const postRevokeDl = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/download/${revokeToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {});
    assert(postRevokeDl.status === 403, 'Recipient access blocked after revocation (HTTP 403 Access Revoked)');

    // 9. Test Passcode Protection
    console.log('\n[TEST 8] Passcode Protection & Verification');
    const passcodeShareRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/shares',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': 'application/json'
      }
    }, {
      file_id: fileIdA,
      expires_in_seconds: 3600,
      one_time: false,
      passcode: '987654'
    });
    const passcodeToken = passcodeShareRes.body.share.token;

    // Download with wrong passcode
    const wrongPassDl = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/download/${passcodeToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { passcode: '000000' });
    assert(wrongPassDl.status === 401, 'Wrong passcode rejected (HTTP 401 Unauthorized)');

    // Download with correct passcode
    const correctPassDl = await request({
      hostname: 'localhost',
      port: PORT,
      path: `/api/shares/download/${passcodeToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { passcode: '987654' });
    assert(correctPassDl.status === 200, 'Correct passcode accepted (HTTP 200 OK)');

    // 10. Verify Security Audit Trail
    console.log('\n[TEST 9] Security Audit Logs');
    const logsRes = await request({
      hostname: 'localhost',
      port: PORT,
      path: '/api/logs',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    assert(logsRes.status === 200 && Array.isArray(logsRes.body.logs) && logsRes.body.logs.length > 0,
      `Audit logs recorded: ${logsRes.body.logs.length} security events tracked`);

    console.log('\n======================================================');
    console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
    console.log('======================================================\n');

    process.exit(failed > 0 ? 1 : 0);
  } catch (err) {
    console.error('Test execution error:', err);
    process.exit(1);
  }
}

// Give server time to bind
setTimeout(runTests, 500);
