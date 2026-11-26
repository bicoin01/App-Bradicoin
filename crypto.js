/* ================================================================
 * BradiCoin Wallet — crypto.js (v2.0.0, hardened)
 * Cryptographic layer: BIP39 + BIP32 master key + secp256k1
 *                      + AES-GCM/PBKDF2 + TOTP + attempt limiting
 *
 * Required libraries (load BEFORE this file):
 *   - crypto-js  (full build: needs SHA256, SHA512, HmacSHA1, PBKDF2)
 *   - elliptic
 *   - bip39 word list: either window.WORD_LIST (2048 words)
 *                      or the `bip39` library (optional but recommended)
 *
 * Public API: window.BradiCrypto (frozen). The old global function
 * names are still exported (read-only) for backward compatibility.
 * ================================================================ */

(function (global) {
  'use strict';

  if (global.BradiCrypto) return; // avoid double-loading / redefinition

  const VERSION = '2.0.0';

  /* ============================================================
   * 0. Helpers
   * ============================================================ */

  function cjs() {
    if (typeof global.CryptoJS === 'undefined') {
      throw new Error('crypto-js library not loaded.');
    }
    return global.CryptoJS;
  }

  function getEC() {
    if (typeof global.elliptic === 'undefined') {
      throw new Error('elliptic library not loaded.');
    }
    if (!getEC.instance) getEC.instance = new global.elliptic.ec('secp256k1');
    return getEC.instance;
  }

  function randomBytes(n) {
    if (!global.crypto || typeof global.crypto.getRandomValues !== 'function') {
      throw new Error('Secure random number generator unavailable.');
    }
    const b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  function getSubtle() {
    if (!global.crypto || !global.crypto.subtle) {
      throw new Error('WebCrypto (crypto.subtle) unavailable. Serve the wallet over HTTPS.');
    }
    return global.crypto.subtle;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  /** Constant-time comparison of two strings. */
  function safeEqual(a, b) {
    a = String(a); b = String(b);
    let diff = a.length ^ b.length;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
  }

  /** Constant-time comparison of two Uint8Arrays. */
  function safeEqualBytes(a, b) {
    let diff = a.length ^ b.length;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) diff |= (a[i] || 0) ^ (b[i] || 0);
    return diff === 0;
  }

  /** Unbiased random string from an alphabet (rejection sampling). */
  function randomString(alphabet, length) {
    const n = alphabet.length;
    const limit = 256 - (256 % n);
    let out = '';
    while (out.length < length) {
      const buf = randomBytes(length * 2);
      for (let i = 0; i < buf.length && out.length < length; i++) {
        if (buf[i] < limit) out += alphabet[buf[i] % n];
      }
    }
    return out;
  }

  /* ============================================================
   * 1. BIP39 — mnemonic generation and validation (12 words)
   * ============================================================ */

  function getWordList() {
    if (Array.isArray(global.WORD_LIST) && global.WORD_LIST.length === 2048) {
      return global.WORD_LIST;
    }
    const lib = global.bip39;
    if (lib && lib.wordlists && lib.wordlists.english && lib.wordlists.english.length === 2048) {
      return lib.wordlists.english;
    }
    throw new Error('BIP39 word list (2048 words) not found. Load bip39 or define WORD_LIST before crypto.js.');
  }

  function normalizeWords(input) {
    if (typeof input === 'string') input = input.trim().split(/\s+/);
    if (!Array.isArray(input)) return [];
    return input.map(w => String(w).trim().toLowerCase()).filter(Boolean);
  }

  /** First 4 bits (hex nibble) of SHA256(entropy) — checksum for 128-bit entropy. */
  function checksumBits(entropyBytes) {
    const C = cjs();
    const hashHex = C.SHA256(C.enc.Hex.parse(bytesToHex(entropyBytes))).toString();
    return parseInt(hashHex[0], 16).toString(2).padStart(4, '0');
  }

  /** Generates a 12-word BIP39 mnemonic with a valid checksum. */
  function generateSeedPhrase() {
    const words = getWordList();
    const entropy = randomBytes(16); // 128 bits

    const entropyBits = Array.from(entropy)
      .map(b => b.toString(2).padStart(8, '0'))
      .join('');
    const fullBits = entropyBits + checksumBits(entropy);

    const result = [];
    for (let i = 0; i < 12; i++) {
      result.push(words[parseInt(fullBits.slice(i * 11, (i + 1) * 11), 2)]);
    }
    return result;
  }

  /** Validates a 12-word BIP39 mnemonic (word list AND checksum). */
  function validateSeedPhrase(input) {
    const words = normalizeWords(input);
    if (words.length !== 12) return false;

    try {
      const lib = global.bip39;
      if (lib && typeof lib.validateMnemonic === 'function') {
        return !!lib.validateMnemonic(words.join(' '));
      }

      const list = getWordList();
      const index = new Map(list.map((w, i) => [w, i]));
      let bits = '';
      for (const w of words) {
        const i = index.get(w);
        if (i === undefined) return false;
        bits += i.toString(2).padStart(11, '0');
      }
      const entropy = bits.slice(0, 128).match(/.{8}/g).map(b => parseInt(b, 2));
      return checksumBits(entropy) === bits.slice(128);
    } catch (e) {
      return false;
    }
  }

  /* ============================================================
   * 2. Password strength
   *    The password is the ONLY thing protecting the encrypted
   *    seed at rest, so the bar is deliberately higher.
   * ============================================================ */

  const MIN_PASSWORD_LENGTH = 12;
  const MAX_PASSWORD_LENGTH = 1024;
  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'passw0rd', 'qwerty', 'qwertyuiop', 'asdfghjkl',
    'letmein', 'welcome', 'welcome1', 'iloveyou', 'admin', 'admin123',
    'abc123', 'monkey', 'dragon', 'master', 'senha', 'senha123', 'mudar123',
    'bradicoin', 'bradicoin1', 'bradicoin123', 'bitcoin', 'bitcoin123',
    'crypto', 'crypto123', 'wallet', 'wallet123'
  ]);

  function validatePasswordStrength(password) {
    if (typeof password !== 'string') {
      return { ok: false, reason: 'Invalid password' };
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      return { ok: false, reason: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long` };
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      return { ok: false, reason: 'Password is too long' };
    }
    if (!/[A-Za-z]/.test(password)) {
      return { ok: false, reason: 'Password must contain at least one letter' };
    }
    if (!/[0-9]/.test(password)) {
      return { ok: false, reason: 'Password must contain at least one number' };
    }
    if (new Set(password).size < 5) {
      return { ok: false, reason: 'Password is too repetitive' };
    }
    const lower = password.toLowerCase();
    const stripped = lower.replace(/[0-9!@#$%^&*._-]+$/g, '');
    if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(stripped)) {
      return { ok: false, reason: 'Password is too common' };
    }
    return { ok: true };
  }

  /* ============================================================
   * 3. Seed encryption (AES-256-GCM + PBKDF2-SHA256)
   *
   *  v2 blob : "v2." + base64( 0x02 | iterations(4, BE) | salt(16) | iv(12) | ct+tag )
   *            The 5-byte header is authenticated as AES-GCM AAD.
   *  legacy  : base64( salt(16) | iv(12) | ct+tag ), 210k iterations
   *            (still decryptable so existing wallets keep working)
   * ============================================================ */

  const KDF_ITERATIONS    = 600000; // OWASP 2023 for PBKDF2-HMAC-SHA256
  const LEGACY_ITERATIONS = 210000;
  const MIN_ITERATIONS    = 100000;
  const MAX_ITERATIONS    = 10000000; // sanity cap against tampered blobs
  const BLOB_PREFIX       = 'v2.';
  const BLOB_VERSION      = 2;
  const SALT_LEN = 16, IV_LEN = 12, TAG_LEN = 16, HEADER_LEN = 5;

  async function deriveKey(password, salt, iterations) {
    const subtle = getSubtle();
    const baseKey = await subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /** Encrypts the seed with the user's password. Returns a string ready to store. */
  async function encryptSeed(seedStr, password) {
    if (typeof seedStr !== 'string' || !seedStr) throw new Error('Invalid seed');
    if (typeof password !== 'string' || !password) throw new Error('Invalid password');

    const subtle = getSubtle();
    const salt = randomBytes(SALT_LEN);
    const iv   = randomBytes(IV_LEN);

    const header = new Uint8Array(HEADER_LEN);
    header[0] = BLOB_VERSION;
    new DataView(header.buffer).setUint32(1, KDF_ITERATIONS);

    const key = await deriveKey(password.normalize('NFKC'), salt, KDF_ITERATIONS);
    const ct = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: iv, additionalData: header },
      key,
      new TextEncoder().encode(seedStr)
    ));

    const out = new Uint8Array(HEADER_LEN + SALT_LEN + IV_LEN + ct.length);
    out.set(header, 0);
    out.set(salt, HEADER_LEN);
    out.set(iv, HEADER_LEN + SALT_LEN);
    out.set(ct, HEADER_LEN + SALT_LEN + IV_LEN);
    return BLOB_PREFIX + bytesToB64(out);
  }

  /**
   * Decrypts the seed. Returns the plaintext, or null if the password is
   * wrong or the data is corrupted / tampered with.
   */
  async function decryptSeed(encrypted, password) {
    try {
      if (typeof encrypted !== 'string' || typeof password !== 'string' || !encrypted || !password) {
        return null;
      }
      const subtle = getSubtle();

      if (encrypted.startsWith(BLOB_PREFIX)) {
        const raw = b64ToBytes(encrypted.slice(BLOB_PREFIX.length));
        if (raw.length < HEADER_LEN + SALT_LEN + IV_LEN + TAG_LEN) return null;
        if (raw[0] !== BLOB_VERSION) return null;

        const iterations = new DataView(raw.buffer, raw.byteOffset + 1, 4).getUint32(0);
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) return null;

        const header = raw.slice(0, HEADER_LEN);
        const salt   = raw.slice(HEADER_LEN, HEADER_LEN + SALT_LEN);
        const iv     = raw.slice(HEADER_LEN + SALT_LEN, HEADER_LEN + SALT_LEN + IV_LEN);
        const ct     = raw.slice(HEADER_LEN + SALT_LEN + IV_LEN);

        const key = await deriveKey(password.normalize('NFKC'), salt, iterations);
        const pt = await subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: header }, key, ct);
        return new TextDecoder().decode(pt);
      }

      // Legacy format (no header, no AAD, password used as typed)
      const raw = b64ToBytes(encrypted);
      if (raw.length < SALT_LEN + IV_LEN + TAG_LEN) return null;
      const salt = raw.slice(0, SALT_LEN);
      const iv   = raw.slice(SALT_LEN, SALT_LEN + IV_LEN);
      const ct   = raw.slice(SALT_LEN + IV_LEN);
      const key = await deriveKey(password, salt, LEGACY_ITERATIONS);
      const pt = await subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
      return new TextDecoder().decode(pt);
    } catch (e) {
      // AES-GCM tag mismatch = wrong password or tampered data
      return null;
    }
  }

  /** True if the stored blob uses the legacy format or fewer iterations than today's default. */
  function encryptedSeedNeedsUpgrade(encrypted) {
    try {
      if (typeof encrypted !== 'string') return false;
      if (!encrypted.startsWith(BLOB_PREFIX)) return true;
      const raw = b64ToBytes(encrypted.slice(BLOB_PREFIX.length));
      const iterations = new DataView(raw.buffer, raw.byteOffset + 1, 4).getUint32(0);
      return iterations < KDF_ITERATIONS;
    } catch (e) {
      return false;
    }
  }

  /**
   * Re-encrypts an old blob with the current format. Call right after a
   * successful unlock. Returns the new blob, or null if the password is wrong.
   */
  async function upgradeEncryptedSeed(encrypted, password) {
    const seed = await decryptSeed(encrypted, password);
    if (seed === null) return null;
    return encryptSeed(seed, password);
  }

  /* ============================================================
   * 4. secp256k1 key pair + BradiCoin address
   * ============================================================ */

  const ADDRESS_RE = /^Br[0-9a-f]{38}$/;

  /** BradiCoin address: "Br" + first 38 hex chars of SHA256(compressed public key). */
  function addressFromPublicKey(publicKeyHex) {
    return 'Br' + cjs().SHA256(publicKeyHex).toString().substring(0, 38);
  }

  function isValidAddress(address) {
    return typeof address === 'string' && ADDRESS_RE.test(address);
  }

  /**
   * Standard derivation: BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds)
   * -> BIP32 master private key (HMAC-SHA512 "Bitcoin seed").
   */
  function derivePrivateKeyStandard(words) {
    const C = cjs();
    if (!C.algo || !C.algo.SHA512 || !C.PBKDF2 || !C.HmacSHA512) {
      throw new Error('crypto-js build is missing SHA512/PBKDF2/HmacSHA512. Use the full crypto-js bundle.');
    }
    const mnemonic = words.join(' ').normalize('NFKD');
    const seed = C.PBKDF2(mnemonic, 'mnemonic', {
      keySize: 512 / 32,
      iterations: 2048,
      hasher: C.algo.SHA512
    });
    const I = C.HmacSHA512(seed, 'Bitcoin seed').toString(); // 128 hex chars
    return I.slice(0, 64);
  }

  /**
   * Derives private key + public key + address from the seed. Deterministic.
   *
   * options.legacy = true  -> OLD derivation SHA256(mnemonic). Only use it to
   *                           open wallets created by the previous version;
   *                           it is NOT standard and much weaker.
   */
  function generateKeyPairFromSeed(seedWords, options) {
    const legacy = !!(options && options.legacy);
    const words = normalizeWords(seedWords);

    if (words.length !== 12) throw new Error('Seed must have 12 words');
    if (!validateSeedPhrase(words)) throw new Error('Invalid seed phrase (unknown word or bad checksum)');

    const ec = getEC();
    const privHex = legacy
      ? cjs().SHA256(words.join(' ')).toString()
      : derivePrivateKeyStandard(words);

    const priv = new ec.n.constructor(privHex, 16);
    if (priv.isZero() || priv.cmp(ec.n) >= 0) {
      throw new Error('Derived private key is out of range.');
    }

    const keyPair = ec.keyFromPrivate(privHex, 'hex');
    const publicKeyHex = keyPair.getPublic(true, 'hex'); // compressed

    return {
      privateKey: privHex,
      publicKey:  publicKeyHex,
      address:    addressFromPublicKey(publicKeyHex),
      derivation: legacy ? 'legacy-sha256' : 'bip39-bip32-master'
    };
  }

  /* -------- Transaction signing -------- */

  function canonicalAmount(value, field, allowZero) {
    let s;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error(`Invalid ${field}`);
      s = String(value);
    } else if (typeof value === 'string') {
      s = value.trim();
    } else {
      throw new Error(`Invalid ${field}`);
    }
    // Plain decimal only: no exponent notation, no sign, max 18 decimals.
    if (!/^\d+(\.\d{1,18})?$/.test(s)) throw new Error(`Invalid ${field}`);
    if (!allowZero && !/[1-9]/.test(s)) throw new Error(`${field} must be greater than zero`);
    return s;
  }

  function canonicalField(value, field, re) {
    const s = String(value === undefined || value === null ? '' : value);
    if (!re.test(s)) throw new Error(`Invalid ${field}`);
    return s;
  }

  /** Builds the exact string that is hashed and signed (must match the backend). */
  function buildTransactionMessage(txData) {
    if (!txData || typeof txData !== 'object') throw new Error('Invalid transaction');
    if (!isValidAddress(txData.fromAddress)) throw new Error('Invalid fromAddress');
    if (!isValidAddress(txData.toAddress))   throw new Error('Invalid toAddress');

    return [
      txData.fromAddress,
      txData.toAddress,
      canonicalAmount(txData.amount, 'amount', false),
      canonicalAmount(txData.fee === undefined || txData.fee === null || txData.fee === '' ? '0' : txData.fee, 'fee', true),
      canonicalField(txData.nonce, 'nonce', /^\d{1,15}$/),
      canonicalField(txData.timestamp, 'timestamp', /^[^|\r\n]{1,64}$/),
      canonicalField(txData.type || 'transfer', 'type', /^[a-z_]{1,32}$/)
    ].join('|');
  }

  /**
   * Signs a transaction — MUST match the backend verification logic:
   *   hash = SHA256(from|to|amount|fee|nonce|timestamp|type), ECDSA secp256k1,
   *   canonical (low-S) DER signature, hex encoded.
   * Refuses to sign if fromAddress does not belong to the given private key.
   */
  function signTransaction(txData, privateKeyHex) {
    if (typeof privateKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error('Invalid private key');
    }
    const ec = getEC();
    const keyPair = ec.keyFromPrivate(privateKeyHex, 'hex');

    const ownAddress = addressFromPublicKey(keyPair.getPublic(true, 'hex'));
    if (!txData || txData.fromAddress !== ownAddress) {
      throw new Error('fromAddress does not match the signing key');
    }

    const msgHashHex = cjs().SHA256(buildTransactionMessage(txData)).toString();
    const signature  = keyPair.sign(msgHashHex, { canonical: true });

    // Self-check before returning
    if (!keyPair.verify(msgHashHex, signature)) {
      throw new Error('Signature self-check failed');
    }
    return signature.toDER('hex');
  }

  /* ============================================================
   * 5. Referral code (not a secret)
   * ============================================================ */

  const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I

  function generateReferralCode() {
    return 'BRD-' + randomString(CODE_ALPHABET, 6);
  }

  /* ============================================================
   * 6. Attempt limiter (anti brute-force, persistent + escalating)
   *    NOTE: this is a UX/defence-in-depth control only. An attacker who
   *    copies the encrypted seed can attack it offline, ignoring this
   *    limiter; that is why PBKDF2 cost and password strength matter.
   * ============================================================ */

  function createAttemptGuard(name, cfg) {
    const maxAttempts = (cfg && cfg.maxAttempts) || 5;
    const baseLockMs  = (cfg && cfg.baseLockMs)  || 5 * 60 * 1000;
    const maxLockMs   = (cfg && cfg.maxLockMs)   || 60 * 60 * 1000;
    const KEY = 'bradicoin.guard.' + name;

    function load() {
      try {
        const raw = global.localStorage && global.localStorage.getItem(KEY);
        if (raw) {
          const s = JSON.parse(raw);
          if (s && Number.isFinite(s.fails) && Number.isFinite(s.strikes) && Number.isFinite(s.lockedUntil)) {
            return { fails: s.fails, strikes: s.strikes, lockedUntil: s.lockedUntil };
          }
        }
      } catch (e) { /* storage unavailable */ }
      return { fails: 0, strikes: 0, lockedUntil: 0 };
    }

    function save() {
      try { global.localStorage && global.localStorage.setItem(KEY, JSON.stringify(state)); }
      catch (e) { /* storage unavailable */ }
    }

    let state = load();

    return {
      canTry() {
        const now = Date.now();
        if (now < state.lockedUntil) {
          const secs = Math.ceil((state.lockedUntil - now) / 1000);
          return { ok: false, reason: `Locked. Try again in ${secs}s.` };
        }
        return { ok: true };
      },
      registerFail() {
        state.fails++;
        if (state.fails >= maxAttempts) {
          state.strikes++;
          const lockMs = Math.min(baseLockMs * Math.pow(2, state.strikes - 1), maxLockMs);
          state.lockedUntil = Date.now() + lockMs;
          state.fails = 0;
          save();
          return { ok: false, reason: `Too many attempts. Locked for ${Math.round(lockMs / 60000)} minute(s).` };
        }
        save();
        return { ok: false, reason: `Wrong password. ${maxAttempts - state.fails} attempt(s) left.` };
      },
      reset() {
        state = { fails: 0, strikes: 0, lockedUntil: 0 };
        save();
      }
    };
  }

  const unlockGuard = createAttemptGuard('unlock');
  const twoFAGuard  = createAttemptGuard('2fa', { maxAttempts: 5, baseLockMs: 60 * 1000, maxLockMs: 30 * 60 * 1000 });

  /* ============================================================
   * 7. 2FA (TOTP, RFC 6238, SHA1, 6 digits, 30 s)
   *
   *  IMPORTANT: a TOTP secret that lives in the browser protects against
   *  nothing if the attacker controls the device/browser. For real account
   *  security, verify the code on the SERVER. This client-side check is
   *  suitable only as an extra confirmation step in the wallet UI.
   * ============================================================ */

  const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Encode(bytes) {
    let bits = '';
    for (let i = 0; i < bytes.length; i++) bits += bytes[i].toString(2).padStart(8, '0');
    let out = '';
    for (let i = 0; i + 5 <= bits.length; i += 5) out += BASE32[parseInt(bits.slice(i, i + 5), 2)];
    return out;
  }

  function base32Decode(b32) {
    const clean = String(b32).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
    if (!clean) throw new Error('Invalid Base32');
    let bits = '';
    for (const ch of clean) {
      const idx = BASE32.indexOf(ch);
      if (idx < 0) throw new Error('Invalid Base32');
      bits += idx.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return new Uint8Array(bytes);
  }

  /** 160-bit random secret, Base32 (32 chars), as recommended by RFC 4226. */
  function generate2FASecret() {
    return base32Encode(randomBytes(20));
  }

  function hotp(keyBytes, counter) {
    const C = cjs();
    const buf = new Uint8Array(8);
    const view = new DataView(buf.buffer);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);

    const hmacHex = C.HmacSHA1(
      C.enc.Hex.parse(bytesToHex(buf)),
      C.enc.Hex.parse(bytesToHex(keyBytes))
    ).toString();

    const offset = parseInt(hmacHex.slice(-1), 16);
    const bin = parseInt(hmacHex.slice(offset * 2, offset * 2 + 8), 16) & 0x7fffffff;
    return String(bin % 1000000).padStart(6, '0');
  }

  /** Returns the matching time step (±1 window) or null. Checks all steps in constant time. */
  function findTotpStep(code, secretB32) {
    const key = base32Decode(secretB32);
    const now = Math.floor(Date.now() / 1000 / 30);
    let matched = null;
    for (let w = -1; w <= 1; w++) {
      const step = now + w;
      if (safeEqual(hotp(key, step), code)) matched = step;
    }
    return matched;
  }

  const lastAcceptedStep = new Map(); // secret -> last accepted time step (anti-replay, per session)

  /**
   * Verifies a 6-digit TOTP code (±30 s tolerance).
   * - rejects malformed codes
   * - rejects re-use of an already accepted code
   * - rate-limited through twoFAGuard
   */
  function verify2FA(code, secret) {
    if (!code || !secret) return false;
    if (!twoFAGuard.canTry().ok) return false;

    const c = String(code).replace(/\s/g, '');
    if (!/^\d{6}$/.test(c)) {
      twoFAGuard.registerFail();
      return false;
    }

    let step;
    try {
      step = findTotpStep(c, secret);
    } catch (e) {
      console.error('verify2FA error:', e);
      return false;
    }

    if (step === null) {
      twoFAGuard.registerFail();
      return false;
    }
    const last = lastAcceptedStep.has(secret) ? lastAcceptedStep.get(secret) : -1;
    if (step <= last) return false; // replayed code
    lastAcceptedStep.set(secret, step);
    twoFAGuard.reset();
    return true;
  }

  /** Builds the otpauth:// URI for the authenticator-app QR code. */
  function build2FAUri(secret, label) {
    const issuer = 'BradiCoin';
    const cleanSecret = String(secret || '').toUpperCase().replace(/\s/g, '');
    if (!/^[A-Z2-7]+$/.test(cleanSecret)) throw new Error('Invalid 2FA secret');
    const account = encodeURIComponent(label || 'user');
    return `otpauth://totp/${encodeURIComponent(issuer)}:${account}` +
           `?secret=${cleanSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  }

  /* -------- Backup codes (store only the hashes) -------- */

  const BACKUP_ITERATIONS = 100000;

  function normalizeBackupCode(code) {
    return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  /** 8 single-use codes, format XXXX-XXXX. Show them once; store hashBackupCode() results. */
  function generateBackupCodes() {
    const codes = [];
    for (let c = 0; c < 8; c++) {
      const code = randomString(CODE_ALPHABET, 8);
      codes.push(code.slice(0, 4) + '-' + code.slice(4));
    }
    return codes;
  }

  async function pbkdf2Bits(secretStr, salt) {
    const subtle = getSubtle();
    const baseKey = await subtle.importKey('raw', new TextEncoder().encode(secretStr), { name: 'PBKDF2' }, false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: BACKUP_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    ));
  }

  /** Returns "bc1$<salt b64>$<hash b64>" — safe to persist. */
  async function hashBackupCode(code) {
    const normalized = normalizeBackupCode(code);
    if (normalized.length !== 8) throw new Error('Invalid backup code');
    const salt = randomBytes(16);
    const hash = await pbkdf2Bits(normalized, salt);
    return 'bc1$' + bytesToB64(salt) + '$' + bytesToB64(hash);
  }

  /** Returns the index of the matching stored hash, or -1. The caller must delete the used hash. */
  async function verifyBackupCode(code, storedHashes) {
    const normalized = normalizeBackupCode(code);
    if (normalized.length !== 8 || !Array.isArray(storedHashes)) return -1;
    let found = -1;
    for (let i = 0; i < storedHashes.length; i++) {
      try {
        const parts = String(storedHashes[i]).split('$');
        if (parts.length !== 3 || parts[0] !== 'bc1') continue;
        const expected = b64ToBytes(parts[2]);
        const actual = await pbkdf2Bits(normalized, b64ToBytes(parts[1]));
        if (safeEqualBytes(actual, expected)) found = i;
      } catch (e) { /* skip malformed entry */ }
    }
    return found;
  }

  /* ============================================================
   * 8. Exports
   * ============================================================ */

  const api = Object.freeze({
    version: VERSION,
    // seed / password
    generateSeedPhrase,
    validateSeedPhrase,
    validatePasswordStrength,
    // encryption at rest
    encryptSeed,
    decryptSeed,
    encryptedSeedNeedsUpgrade,
    upgradeEncryptedSeed,
    // keys / transactions
    generateKeyPairFromSeed,
    addressFromPublicKey,
    isValidAddress,
    buildTransactionMessage,
    signTransaction,
    // misc
    generateReferralCode,
    // 2FA
    generate2FASecret,
    generateBackupCodes,
    hashBackupCode,
    verifyBackupCode,
    verify2FA,
    build2FAUri,
    // rate limiting
    unlockGuard,
    twoFAGuard
  });

  function define(name, value) {
    Object.defineProperty(global, name, {
      value: value, writable: false, configurable: false, enumerable: true
    });
  }

  define('BradiCrypto', api);

  // Backward-compatible globals (read-only so other scripts cannot swap them out)
  Object.keys(api).forEach(function (name) {
    if (name === 'version') return;
    try { define(name, api[name]); }
    catch (e) { console.warn('crypto.js: could not define global "' + name + '"; use BradiCrypto.' + name); }
  });

})(typeof window !== 'undefined' ? window : globalThis);
