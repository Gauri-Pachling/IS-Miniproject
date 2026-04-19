/**
 * ═══════════════════════════════════════════════════════════════════════════
 *   WebCrypto Utility — Hybrid Cryptosystem
 *   All cryptographic operations are performed EXCLUSIVELY in the browser.
 *   No plaintext ever leaves this device.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Algorithm Suite:
 *   Symmetric  : AES-256-GCM      (NIST SP 800-38D)
 *   Asymmetric : RSA-4096-OAEP    (PKCS#1 v2.2 / RFC 8017)
 *   Signature  : ECDSA P-256      (FIPS 186-4)
 *   KDF        : PBKDF2-SHA256    (NIST SP 800-132) — optional password layer
 *   Random     : window.crypto.getRandomValues (CSPRNG)
 */

const subtle = window.crypto.subtle;

// ─── Helpers ────────────────────────────────────────────────────────────────

export const toBase64 = (buffer) => {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (let b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
};

export const fromBase64 = (b64) => {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
};

export const randomBytes = (n) =>
  window.crypto.getRandomValues(new Uint8Array(n));

export const toHex = (buffer) =>
  Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

// ─── AES-256-GCM ─────────────────────────────────────────────────────────────

/**
 * Generates a fresh AES-256-GCM session key.
 * Returns a non-extractable CryptoKey by default; extractable=true is needed
 * for the wrapKey step.
 */
export const generateAESKey = () =>
  subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,            // extractable — needed for RSA wrapping
    ['encrypt', 'decrypt']
  );

/**
 * Imports raw AES key bytes (32 bytes) returned by the server after RSA decapsulation.
 */
export const importRawAESKey = (rawKeyBytes) =>
  subtle.importKey(
    'raw',
    rawKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

/**
 * Encrypts arbitrary binary data with AES-256-GCM.
 *
 * Returns:
 *   { ciphertext: ArrayBuffer, iv: Uint8Array(12), ivBase64: string }
 *
 * The WebCrypto API automatically appends the 128-bit GCM authentication tag
 * to the ciphertext — no manual MAC step required.
 */
export const encryptAES = async (data, aesKey) => {
  const iv = randomBytes(12);   // 96-bit nonce — NIST recommended for GCM
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    data
  );
  return {
    ciphertext,
    iv,
    ivBase64:    toBase64(iv),
    keyBits:     256,
    ivBits:      96,
    tagBits:     128,
    algorithm:   'AES-256-GCM',
  };
};

/**
 * Decrypts AES-256-GCM ciphertext.
 *
 * Throws a DOMException ("The operation failed") if the authentication tag
 * does not match — this is the TAMPER DETECTION mechanism.
 * The UI catches this specific error and displays a Tamper Alert.
 */
export const decryptAES = async (ciphertextBuffer, aesKey, ivBase64) => {
  const iv = new Uint8Array(fromBase64(ivBase64));
  return subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    aesKey,
    ciphertextBuffer
  );
};

// ─── RSA-4096-OAEP ───────────────────────────────────────────────────────────

/**
 * Imports the server's RSA-4096 public key from Base64-encoded SPKI bytes.
 * Algorithm must match the server: RSA-OAEP with SHA-256.
 */
export const importRSAPublicKey = (spkiBase64) =>
  subtle.importKey(
    'spki',
    fromBase64(spkiBase64),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['wrapKey']        // only used for key encapsulation
  );

/**
 * Key Encapsulation: wraps (encrypts) the AES session key with the server's
 * RSA-4096-OAEP public key.
 *
 * The server decrypts this on the /decrypt endpoint using its private key.
 */
export const wrapAESKeyWithRSA = (aesKey, rsaPublicKey) =>
  subtle.wrapKey('raw', aesKey, rsaPublicKey, { name: 'RSA-OAEP' });

// ─── ECDSA-P256 Digital Signature ────────────────────────────────────────────

/**
 * Generates an ephemeral ECDSA P-256 signing key pair for this session.
 * The private key never leaves the browser.
 * The public key is stored server-side for later verification.
 */
export const generateSigningKeyPair = () =>
  subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

/**
 * Signs arbitrary data with the sender's ECDSA private key.
 * Provides non-repudiation: proves who encrypted the file.
 */
export const signData = (data, privateKey) =>
  subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );

/**
 * Verifies an ECDSA signature (browser-side verification for UX feedback).
 * The server also verifies on the /verify endpoint.
 */
export const verifySignature = async (data, signatureBase64, publicKey) =>
  subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    fromBase64(signatureBase64),
    data
  );

/**
 * Exports a CryptoKey public key to Base64-encoded SPKI format for server storage.
 */
export const exportPublicKey = async (publicKey) => {
  const spki = await subtle.exportKey('spki', publicKey);
  return toBase64(spki);
};

// ─── PBKDF2 — Optional Password Protection Layer ─────────────────────────────

/**
 * Derives an AES-256 wrapping key from a user password using PBKDF2-SHA256.
 *
 * Parameters follow OWASP recommendations:
 *   Iterations : 310,000  (OWASP 2023 minimum for PBKDF2-SHA256)
 *   Salt       : 128-bit random
 *
 * This wrapping key is used to additionally encrypt (wrap) the AES session key,
 * creating a two-factor envelope: knowledge (password) + possession (server key).
 */
export const deriveKeyFromPassword = async (password, saltBytes) => {
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return subtle.deriveKey(
    {
      name:       'PBKDF2',
      salt:       saltBytes,
      iterations: 310_000,
      hash:       'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey']
  );
};

/**
 * Wraps the AES session key with the PBKDF2-derived password key.
 * Produces an additional layer of encryption over the session key.
 */
export const wrapKeyWithPassword = async (aesKey, passwordKey) => {
  const wrapIv = randomBytes(12);
  const wrapped = await subtle.wrapKey(
    'raw', aesKey, passwordKey,
    { name: 'AES-GCM', iv: wrapIv, tagLength: 128 }
  );
  return { wrapped, wrapIv };
};

export const unwrapKeyWithPassword = async (pwWrappedBase64, pwWrapIvBase64, pbkdf2SaltBase64, password) => {
  const salt      = new Uint8Array(fromBase64(pbkdf2SaltBase64));
  const passwordKey = await deriveKeyFromPassword(password, salt);
  const wrapIv    = new Uint8Array(fromBase64(pwWrapIvBase64));
  return subtle.unwrapKey(
    'raw',
    fromBase64(pwWrappedBase64),
    passwordKey,
    { name: 'AES-GCM', iv: wrapIv, tagLength: 128 },
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
};

// ─── Full Hybrid Encrypt Flow ─────────────────────────────────────────────────

/**
 * Performs the complete hybrid encryption of a File object.
 *
 * Flow:
 *   1. Read file as ArrayBuffer
 *   2. Generate AES-256-GCM session key
 *   3. Encrypt file:     ciphertext = AES-256-GCM( plaintext, sessionKey, IV )
 *   4. Wrap session key: encKey     = RSA-4096-OAEP( sessionKey, serverPubKey )
 *   5. Sign ciphertext:  sig        = ECDSA-P256( ciphertext, signingPrivKey )
 *   6. [Optional] PBKDF2 wrap of session key with password
 *
 * Returns the complete digital envelope payload ready to POST to the server.
 *
 * @param {File}       file           - File object to encrypt
 * @param {CryptoKey}  rsaPublicKey   - Server's RSA-4096-OAEP public key
 * @param {CryptoKey}  signingPrivKey - Sender's ECDSA P-256 private key
 * @param {CryptoKey}  signingPubKey  - Sender's ECDSA P-256 public key (for server storage)
 * @param {string|null} password      - Optional password for PBKDF2 layer
 * @param {Function}   onProgress     - Progress callback (0–100)
 */
export const hybridEncryptFile = async (
  file,
  rsaPublicKey,
  signingPrivKey,
  signingPubKey,
  password = null,
  onProgress = () => {}
) => {
  const log = [];
  const addLog = (msg, detail = '') => {
    log.push({ ts: Date.now(), msg, detail });
    onProgress(log.length);
  };

  // Step 1: Read file
  addLog('Reading file into ArrayBuffer...');
  const plaintext = await file.arrayBuffer();

  // Step 2: Generate AES-256-GCM session key
  addLog('Generating AES-256-GCM session key (256-bit)...');
  const aesKey = await generateAESKey();

  // Step 3: Encrypt file with AES-256-GCM
  addLog('Encrypting file with AES-256-GCM (96-bit IV, 128-bit auth tag)...');
  const { ciphertext, iv, ivBase64, keyBits, ivBits, tagBits, algorithm } =
    await encryptAES(plaintext, aesKey);
  addLog(`Encryption complete.`, `IV: ${toHex(iv)} | KeyBits: ${keyBits} | TagBits: ${tagBits}`);

  // Step 4: Wrap session key with RSA-4096-OAEP
  addLog('Wrapping session key with RSA-4096-OAEP (SHA-256)...');
  const wrappedKey = await wrapAESKeyWithRSA(aesKey, rsaPublicKey);
  addLog('Session key wrapped.', `RSA-OAEP-SHA256 | KeyBits: 4096`);

  // Step 5: Sign the ciphertext with ECDSA-P256
  addLog('Signing ciphertext with ECDSA-P256 / SHA-256...');
  const signature    = await signData(ciphertext, signingPrivKey);
  const sigPubKeyB64 = await exportPublicKey(signingPubKey);
  addLog('Signature generated.', `Algorithm: ECDSA-P256-SHA256`);

  // Step 6: Optional PBKDF2 password layer
  let pbkdf2SaltBase64 = null;
  let passwordProtected = false;
  // NEW
  let pwWrappedAesKeyBase64 = null;
  let pwWrapIvBase64        = null;
  if (password) {
    addLog('Applying PBKDF2 password layer (SHA-256, 310,000 iterations)...');
    const salt = randomBytes(16);
    pbkdf2SaltBase64 = toBase64(salt);
    const passKey = await deriveKeyFromPassword(password, salt);
    const { wrapped: pwWrapped, wrapIv } = await wrapKeyWithPassword(aesKey, passKey);
    pwWrappedAesKeyBase64 = toBase64(pwWrapped);
    pwWrapIvBase64        = toBase64(wrapIv);
    passwordProtected     = true;
    addLog('Password layer applied.', `PBKDF2-SHA256 | Iterations: 310,000 | Salt: ${toHex(salt)}`);
  }

  return {
    // Envelope payload
    fileName:              file.name,
    fileType:              file.type || 'application/octet-stream',
    fileSizeBytes:         file.size,
    encryptedFileBase64:   toBase64(ciphertext),
    ivBase64,
    encryptedAesKeyBase64: toBase64(wrappedKey),
    signatureBase64:       toBase64(signature),
    signingPublicKeyBase64: sigPubKeyB64,
    passwordProtected,
    pbkdf2SaltBase64,
    // add alongside pbkdf2SaltBase64 in the return payload
    pwWrappedAesKeyBase64,
    pwWrapIvBase64,
    // Crypto parameter transparency
    cryptoParams: {
      aesKeyBits:    keyBits,
      ivBits,
      tagBits,
      ivHex:         toHex(iv),
      symAlgorithm:  algorithm,
      asymAlgorithm: 'RSA-4096-OAEP-SHA256',
      sigAlgorithm:  'ECDSA-P256-SHA256',
      rsaKeyBits:    4096,
      pbkdf2:        passwordProtected ? 'PBKDF2-SHA256-310000' : 'none',
    },
    log,
  };
};

// ─── Full Hybrid Decrypt Flow ─────────────────────────────────────────────────

/**
 * Decrypts an envelope using the unwrapped AES key returned by the server.
 *
 * If the GCM authentication tag does not match (tampered ciphertext),
 * this function throws with { tampered: true }.
 */
// NEW
export const hybridDecryptEnvelope = async (serverResponse, password = null) => {
  const {
    encryptedFileBase64, ivBase64, fileName,
    rawAesKeyBase64,
    passwordProtected, pwWrappedAesKeyBase64, pwWrapIvBase64, pbkdf2SaltBase64,
  } = serverResponse;

  let aesKey;
  if (passwordProtected) {
    if (!password) throw new Error('Password required to decrypt this envelope.');
    try {
      aesKey = await unwrapKeyWithPassword(
        pwWrappedAesKeyBase64, pwWrapIvBase64, pbkdf2SaltBase64, password
      );
    } catch {
      throw new Error('Incorrect password — PBKDF2 key derivation or unwrap failed.');
    }
  } else {
    aesKey = await importRawAESKey(fromBase64(rawAesKeyBase64));
  }

  try {
    const plaintext = await decryptAES(fromBase64(encryptedFileBase64), aesKey, ivBase64);
    return { plaintext, fileName, tampered: false };
  } catch (err) {
    throw { tampered: true, message: 'AES-GCM authentication tag mismatch — ciphertext has been tampered!', raw: err };
  }
};

/**
 * Triggers a browser download of a plaintext ArrayBuffer.
 */
export const downloadDecryptedFile = (plaintextBuffer, fileName) => {
  const blob = new Blob([plaintextBuffer]);
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
};
