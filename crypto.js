/* ================================================================
 * BradiCoin Wallet — crypto.js
 * Cryptographic layer (BIP39 + secp256k1 + AES-GCM + TOTP)
 * Must be loaded AFTER these libraries:
 *   - crypto-js
 *   - elliptic
 *   - otpauth (optional, for real 2FA)
 *   - bip39   (optional, for mnemonic generation)
 * ================================================================ */

(function (global) {
  'use strict';

  /* ============================================================
   * 1. BIP39 — Mnemonic generation and validation (12 words)
   * ============================================================ */

  function getWordList() {
    if (Array.isArray(global.WORD_LIST) && global.WORD_LIST.length >= 2048) {
      return global.WORD_LIST;
    }
    if (typeof global.bip39 !== 'undefined' && global.bip39.wordlists?.english) {
      return global.bip39.wordlists.english;
    }
    throw new Error('BIP39 word list not found. Load bip39 or define WORD_LIST before crypto.js.');
  }

  /**
   * Generates a 12-word BIP39 mnemonic with valid checksum.
   * Uses crypto.getRandomValues for secure entropy.
   */
  function generateSeedPhrase() {
    if (typeof global.bip39 !== 'undefined' && global.bip39.generateMnemonic) {
      try {
        return global.bip39.generateMnemonic(128).split(' ');
      } catch (e) {
        console.warn('bip39.generateMnemonic failed, using local fallback:', e);
      }
    }

    const words = getWordList();
    const entropy = new Uint8Array(16); // 128 bits
    crypto.getRandomValues(entropy);

    const hashHex = CryptoJS.SHA256(
      CryptoJS.enc.Hex.parse(bytesToHex(entropy))
    ).toString();
    const checksumBits = parseInt(hashHex[0], 16).toString(2).padStart(4, '0');

    const entropyBits = bytesToHex(entropy)
      .split('')
      .map(c => parseInt(c, 16).toString(2).padStart(4, '0'))
      .join('');

    const fullBits = entropyBits + checksumBits;
    const result = [];
    for (let i = 0; i < 12; i++) {
      const chunk = fullBits.slice(i * 11, (i + 1) * 11);
      result.push(words[parseInt(chunk, 2)]);
    }
    return result;
  }

  /**
   * Validates a BIP39 mnemonic (12 words + checksum).
   */
  function validateSeedPhrase(words) {
    if (typeof words === 'string') {
      words = words.trim().toLowerCase().split(/\s+/);
    }
    if (!Array.isArray(words) || words.length !== 12) return false;

    if (typeof global.bip39 !== 'undefined' && global.bip39.validateMnemonic) {
      try {
        return global.bip39.validateMnemonic(words.join(' '));
      } catch (e) {
        return false;
      }
    }

    try {
      const list = getWordList();
      const set = new Set(list);
      return words.every(w => set.has(w));
    } catch (e) {
      return false;
    }
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /* ============================================================
   * 2. Password strength validation
   * ============================================================ */

  function validatePasswordStrength(password) {
    if (typeof password !== 'string') {
      return { ok: false, reason: 'Invalid password' };
    }
    if (password.length < 8) {
      return { ok: false, reason: 'Password must be at least 8 characters long' };
    }
    if (!/[A-Za-z]/.test(password)) {
      return { ok: false, reason: 'Password must contain at least one letter' };
    }
    if (!/[0-9]/.test(password)) {
      return { ok: false, reason: 'Password must contain at least one number' };
    }
    return { ok: true };
  }

  /* ============================================================
   * 3. Seed encryption (AES-GCM + PBKDF2)
   *    Ciphertext format: base64( salt(16) | iv(12) | ct+tag )
   * ============================================================ */

  const PBKDF2_ITERATIONS = 210000; // OWASP 2023: >= 210k for SHA-256

  function bufToB64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts the seed with the user's password.
   * Returns a base64 string ready to be stored.
   */
  async function encryptSeed(seedStr, password) {
    if (typeof seedStr !== 'string' || !seedStr) throw new Error('Invalid seed');
    if (typeof password !== 'string' || !password) throw new Error('Invalid password');

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const key  = await deriveKey(password, salt);

    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      new TextEncoder().encode(seedStr)
    );

    const ctBytes = new Uint8Array(ct);
    const out = new Uint8Array(salt.length + iv.length + ctBytes.length);
    out.set(salt, 0);
    out.set(iv, salt.length);
    out.set(ctBytes, salt.length + iv.length);

    return bufToB64(out.buffer);
  }

  /**
   * Decrypts the seed with the password.
   * Returns the plaintext seed, or null if the password is wrong.
   */
  async function decryptSeed(encryptedB64, password) {
    try {
      if (!encryptedB64 || !password) return null;
      const raw = new Uint8Array(b64ToBuf(encryptedB64));
      if (raw.length < 16 + 12 + 1) return null;

      const salt = raw.slice(0, 16);
      const iv   = raw.slice(16, 28);
      const ct   = raw.slice(28);

      const key = await deriveKey(password, salt.buffer);

      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ct
      );
      return new TextDecoder().decode(pt);
    } catch (e) {
      // Invalid tag = wrong password (AES-GCM authenticates)
      return null;
    }
  }

  /* ============================================================
   * 4. secp256k1 key pair + BradiCoin address
   * ============================================================ */

  /**
   * Derives private key + public key + address from the seed.
   * Deterministic: same seed -> same address.
   */
  function generateKeyPairFromSeed(seedWords) {
    if (typeof global.elliptic === 'undefined') {
      throw new Error('elliptic library not loaded.');
    }
    const words = Array.isArray(seedWords)
      ? seedWords
      : String(seedWords).trim().toLowerCase().split(/\s+/);

    if (words.length !== 12) {
      throw new Error('Seed must have 12 words');
    }

    const EC = global.elliptic.ec;
    const ec = new EC('secp256k1');

    const seedStr = words.join(' ');
    const privHex = CryptoJS.SHA256(seedStr).toString(); // 64 hex = 32 bytes
    const keyPair = ec.keyFromPrivate(privHex, 'hex');

    const publicKeyHex = keyPair.getPublic(true, 'hex'); // compressed

    // BradiCoin address: Br + first 38 chars of SHA256(publicKey)
    const addrHash = CryptoJS.SHA256(publicKeyHex).toString();
    const address  = 'Br' + addrHash.substring(0, 38);

    return {
      privateKey: privHex,
      publicKey:  publicKeyHex,
      address:    address
    };
  }

  /**
   * Signs a transaction — MUST match the backend verification logic.
   * Backend uses: SHA256(from|to|amount|fee|nonce|timestamp|type) + sign(canonical).
   */
  function signTransaction(txData, privateKeyHex) {
    if (typeof global.elliptic === 'undefined') {
      throw new Error('elliptic library not loaded.');
    }
    const EC = global.elliptic.ec;
    const ec = new EC('secp256k1');
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');

    const msg = [
      txData.fromAddress,
      txData.toAddress,
      txData.amount.toString(),
      (txData.fee || '0').toString(),
      txData.nonce.toString(),
      txData.timestamp,
      txData.type || 'transfer'
    ].join('|');

    const msgHashHex = CryptoJS.SHA256(msg).toString();
    const signature  = keyPair.sign(msgHashHex, { canonical: true });
    return signature.toDER('hex');
  }

  /* ============================================================
   * 5. Referral code
   * ============================================================ */

  function generateReferralCode() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
    const bytes = new Uint8Array(6);
    crypto.getRandomValues(bytes);
    let code = 'BRD-';
    for (let i = 0; i < 6; i++) {
      code += alphabet[bytes[i] % alphabet.length];
    }
    return code;
  }

  /* ============================================================
   * 6. 2FA (TOTP) — uses otpauth if available, otherwise fallback
   * ============================================================ */

  function generate2FASecret() {
    // Base32 secret (32 chars = 160 bits, RFC 4226 recommended size)
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);

    let bits = '';
    for (let i = 0; i < bytes.length; i++) {
      bits += bytes[i].toString(2).padStart(8, '0');
    }
    let secret = '';
    for (let i = 0; i + 5 <= bits.length; i += 5) {
      secret += alphabet[parseInt(bits.slice(i, i + 5), 2)];
    }
    return secret;
  }

  function generateBackupCodes() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const codes = [];
    for (let c = 0; c < 8; c++) {
      const bytes = new Uint8Array(8);
      crypto.getRandomValues(bytes);
      let code = '';
      for (let i = 0; i < 8; i++) code += alphabet[bytes[i] % alphabet.length];
      codes.push(code.slice(0, 4) + '-' + code.slice(4));
    }
    return codes;
  }

  /**
   * Verifies a 6-digit TOTP code.
   * Accepts a ±1 period (30s) window for clock tolerance.
   */
  function verify2FA(code, secret) {
    if (!code || !secret) return false;

    if (typeof global.otpauth !== 'undefined' && global.otpauth.TOTP) {
      try {
        const totp = new global.otpauth.TOTP({ secret, digits: 6, period: 30, algorithm: 'SHA1' });
        const delta = totp.validate({ token: String(code).replace(/\s/g, ''), window: 1 });
        return delta !== null;
      } catch (e) {
        console.warn('otpauth failed, using fallback:', e);
      }
    }
    return verifyTOTPFallback(code, secret);
  }

  // TOTP fallback (RFC 6238, SHA1)
  function verifyTOTPFallback(code, secretB32) {
    try {
      const keyBytes = base32Decode(secretB32);
      const counter = Math.floor(Date.now() / 1000 / 30);

      for (let w = -1; w <= 1; w++) {
        const c = counter + w;
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        view.setUint32(0, Math.floor(c / 0x100000000));
        view.setUint32(4, c & 0xFFFFFFFF);

        const hmacHex = CryptoJS.HmacSHA1(
          CryptoJS.enc.Hex.parse(bytesToHex(new Uint8Array(buf))),
          CryptoJS.enc.Hex.parse(bytesToHex(keyBytes))
        ).toString();

        const offset = parseInt(hmacHex.slice(-1), 16);
        const binary = (
          (parseInt(hmacHex.substr(offset * 2, 2), 16) & 0x7f) << 24 |
          (parseInt(hmacHex.substr(offset * 2 + 2, 2), 16) & 0xff) << 16 |
          (parseInt(hmacHex.substr(offset * 2 + 4, 2), 16) & 0xff) << 8  |
          (parseInt(hmacHex.substr(offset * 2 + 6, 2), 16) & 0xff)
        );

        const otp = String(binary % 1000000).padStart(6, '0');
        if (otp === String(code).replace(/\s/g, '')) return true;
      }
      return false;
    } catch (e) {
      console.error('verifyTOTPFallback error:', e);
      return false;
    }
  }

  function base32Decode(b32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    b32 = String(b32).toUpperCase().replace(/=+$/, '');
    let bits = '';
    for (const ch of b32) {
      const idx = alphabet.indexOf(ch);
      if (idx < 0) throw new Error('Invalid Base32');
      bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return new Uint8Array(bytes);
  }

  /**
   * Builds the otpauth:// URI for the Google Authenticator QR code.
   */
  function build2FAUri(secret, label) {
    const issuer = 'BradiCoin';
    const account = encodeURIComponent(label || 'user');
    return `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
  }

  /* ============================================================
   * 7. Unlock rate limiting (anti brute-force)
   * ============================================================ */

  const unlockGuard = (function () {
    const MAX_ATTEMPTS = 5;
    const LOCK_MS      = 5 * 60 * 1000; // 5 minutes
    let fails = 0;
    let lockedUntil = 0;

    return {
      canTry() {
        const now = Date.now();
        if (now < lockedUntil) {
          const secs = Math.ceil((lockedUntil - now) / 1000);
          return { ok: false, reason: `Locked. Try again in ${secs}s.` };
        }
        return { ok: true };
      },
      registerFail() {
        fails++;
        if (fails >= MAX_ATTEMPTS) {
          lockedUntil = Date.now() + LOCK_MS;
          fails = 0;
          return { ok: false, reason: 'Too many attempts. Locked for 5 minutes.' };
        }
        const remaining = MAX_ATTEMPTS - fails;
        return { ok: false, reason: `Wrong password. ${remaining} attempt(s) left.` };
      },
      reset() {
        fails = 0;
        lockedUntil = 0;
      }
    };
  })();

  /* ============================================================
   * 8. Export everything to window
   * ============================================================ */

  Object.assign(global, {
    generateSeedPhrase,
    validateSeedPhrase,
    validatePasswordStrength,
    encryptSeed,
    decryptSeed,
    generateKeyPairFromSeed,
    signTransaction,
    generateReferralCode,
    generate2FASecret,
    generateBackupCodes,
    verify2FA,
    build2FAUri,
    unlockGuard
  });

  console.log('🔐 crypto.js loaded (BIP39 + AES-GCM + PBKDF2 + secp256k1 + TOTP)');

})(typeof window !== 'undefined' ? window : globalThis);
