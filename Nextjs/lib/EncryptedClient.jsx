class EncryptedClient {

  /* ================= PRIVATE FIELDS ================= */
  #tokenKey;
  #tokenUrl;
  #apiUrl;

  /* ================= CONSTRUCTOR ================= */
  constructor(options = {}) {
    this.#tokenKey = options.tokenKey || "token";
    this.#tokenUrl =
    options.tokenUrl || process.env.NEXT_PUBLIC_API_URL + "/token";
    this.#apiUrl = process.env.NEXT_PUBLIC_API_URL;
  }

  /* ================= PUBLIC ================= */
  async send(url, jsonPayload) {
    try {
      const publicKey = await this.#fetchPublicKey();
      const aesKey = await this.#generateAesKey();

      const encryptedData = await this.#encryptAes(aesKey, jsonPayload);
      const encryptedSessionKey = await this.#encryptAesKey(publicKey, aesKey);

      const data = encryptedData + "." + encryptedSessionKey;

      const response = await fetch(this.#apiUrl + url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: data }),
      });

      if (!response.ok) {
        throw new Error(`HTTP_ERROR_${response.status}`);
      }

      const encryptedResp = await response.json();

      if (!encryptedResp || encryptedResp.success !== true) {
        throw new Error(encryptedResp?.message || "SERVER_ERROR");
      }

      if (!encryptedResp.token) {
        throw new Error("INVALID_SERVER_RESPONSE");
      }

      return await this.#decryptAes(aesKey, encryptedResp.token);
    } catch (err) {
      throw err;
    }
  }

/* ================= PRIVATE: KEY HANDLING ================= */
async #fetchPublicKey() {
  const EXPIRY_MS = 60 * 60 * 1000; // 1 hour (change as needed)
  const expiryKey = `${this.#tokenKey}_expiry`;

  try {
    let pem = localStorage.getItem(this.#tokenKey);
    const expiry = localStorage.getItem(expiryKey);

    const isExpired = !expiry || Date.now() > Number(expiry);

    if (!pem || isExpired) {
      localStorage.removeItem(this.#tokenKey);
      localStorage.removeItem(expiryKey);

      const res = await fetch(this.#tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!res.ok) {
        throw new Error("PUBLIC_KEY_FETCH_FAILED");
      }

      const data = await res.json();

      if (!data || !data.token) {
        throw new Error("INVALID_PUBLIC_KEY_RESPONSE");
      }

      pem = data.token;

      localStorage.setItem(this.#tokenKey, pem);
      localStorage.setItem(
        expiryKey,
        Date.now() + EXPIRY_MS
      );
    }

    return await this.#importRSAPublicKey(pem);
  } catch (err) {
    localStorage.removeItem(this.#tokenKey);
    localStorage.removeItem(`${this.#tokenKey}_expiry`);
    throw err;
  }
}


  async #importRSAPublicKey(pem) {
    try {
      const bin = atob(pem.trim());
      const buf = Uint8Array.from(bin, c => c.charCodeAt(0));

      return await crypto.subtle.importKey(
        "spki",
        buf,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
    } catch {
      throw new Error("PUBLIC_KEY_IMPORT_FAILED");
    }
  }

  async #generateAesKey() {
    return await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /* ================= PRIVATE: AES ================= */

  async #encryptAes(key, json) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(json));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoded
    );

    const encryptedBytes = new Uint8Array(encrypted);
    const tag = encryptedBytes.slice(-16);
    const ciphertext = encryptedBytes.slice(0, -16);

    const combined = new Uint8Array(iv.length + tag.length + ciphertext.length);
    combined.set(iv, 0);
    combined.set(tag, iv.length);
    combined.set(ciphertext, iv.length + tag.length);

    return this.#toBase64(combined);
  }

  async #decryptAes(aesKey, base64Data) {
    if (!aesKey) throw new Error("Missing AES key");

    const raw = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));

    const iv = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const ciphertext = raw.slice(28);

    const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
    ctWithTag.set(ciphertext, 0);
    ctWithTag.set(tag, ciphertext.length);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      ctWithTag
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  /* ================= PRIVATE: RSA ================= */

  async #encryptAesKey(publicKey, aesKey) {
    const raw = await crypto.subtle.exportKey("raw", aesKey);

    const encrypted = await crypto.subtle.encrypt(
      { name: "RSA-OAEP", hash: "SHA-256" },
      publicKey,
      raw
    );

    return this.#toBase64(encrypted);
  }

  /* ================= PRIVATE: UTIL ================= */

  #toBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

export default EncryptedClient;