import crypto from "crypto";
import fs from "fs";

class EncryptedServer {
  decryptedData;
  aesKey;
  privateKey;
  publicKey;

  
  constructor(
    privateKeyPath = "private.pem",
    publicKeyPath = "public.pem"
  ) {
    this.privateKey = fs.readFileSync(privateKeyPath, "utf8");
    this.publicKey = fs.readFileSync(publicKeyPath, "utf8");
    // this.privateKey = process.env.PRIVATE_KEY;
    // this.publicKey = process.env.PUBLIC_KEY;
  }

  /* ================= PUBLIC KEY ================= */
  getPublicKeyBase64() {
    return this.publicKey.replace(
      /-----(BEGIN|END) PUBLIC KEY-----|\s+/g,
      ""
    );
  }

  /* ================= RSA ================= */
decryptAesKey(encryptedBase64) {
  const encrypted = Buffer.from(encryptedBase64, "base64");

  try {
    const key = crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      encrypted
    );

    if (key.length !== 32) {
      throw new Error("Invalid AES key length");
    }

    return key;
  } catch (e) {
    console.warn("RSA decrypt failed:", e.message);
    throw new Error("RSA decrypt failed : " + e.message);
  }
}


encryptAesKey(aesKeyBuffer) {
  try {
    const encrypted = crypto.publicEncrypt(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKeyBuffer // Buffer (32 bytes)
    );

    return encrypted.toString("base64");
  } catch (err) {
    throw new Error("RSA_ENCRYPTION_FAILED");
  }
}


  /* ================= AES ================= */
  /* 
  encryptedBase64 : String
  aesKey : buffer
  */
  decryptAes(encryptedBase64, aesKey) {
    if (aesKey.length !== 32) {
        throw new Error("Invalid AES key length");
    }
    const raw = Buffer.from(encryptedBase64, "base64");
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const ciphertext = raw.subarray(28);

    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        aesKey,
        iv
      );

      decipher.setAuthTag(tag);

      const decryptedBuffer = Buffer.concat([
        decipher.update(ciphertext), // ✅ NO encoding here
        decipher.final()
      ]);

      return JSON.parse(decryptedBuffer.toString("utf8")); // ✅ convert AFTER
    } catch (e) {
      throw new Error("AES decrypt failed");
    }
  }


  encryptAes(payload, aesKey) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      "aes-256-gcm",
      aesKey,
      iv
    );
    const encryptedBuffer = Buffer.concat([
      cipher.update(JSON.stringify(payload), "utf8"),
      cipher.final()
    ]);

    const tag = cipher.getAuthTag(); // 16 bytes
    return Buffer.concat([iv, tag, encryptedBuffer]).toString("base64");
  }


  /* ================= KEY GENERATION ================= */
  static generatePublicPrivateKey(
    privateKeyPath = "private.pem",
    publicKeyPath = "public.pem",
    bits = 2048
  ) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: bits,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });
  }

  /* ================= CLIENT REQUEST ================= */
  decryptResponse(payload) {
    if (!payload?.token) {
      throw new Error("Token missing");
    }

    if (!payload.token.includes(".")) {
      throw new Error("Invalid token format");
    }

    const [encryptedData, encryptedSessionKey] =
      payload.token.split(".", 2);
    this.aesKey = this.decryptAesKey(encryptedSessionKey);
    this.decryptedData = this.decryptAes(
      encryptedData,
      this.aesKey
    );

    return this.decryptedData;
  }


  /* 
 "aesKey": {
    "type": "Buffer",
    "data": [
      250, 107, 40, 16, 49, 170, 211, 160,
      82, 19, 69, 239, 184, 130, 31, 104,
      240, 151, 140, 53, 218, 162, 13, 250,
      44, 225, 66, ...
    ]
  }
 */
  async generateAesKey() {
    return crypto.randomBytes(32);
  }


  /* ================= RESPONSES ================= */

  // Response With Aes Key
  responseSuccess(payload, message) {
    const token = this.encryptAes(payload, this.aesKey);
    return JSON.stringify({
      success: true,
      token,
      ...(message && { message }),
    });
  }

  responseSuccessPlain(payload, message) {
    return JSON.stringify({
      success: true,
      data: payload,
      ...(message && { message }),
    });
  }

  responsePublicKey() {
    return JSON.stringify({
      success: true,
      token: this.getPublicKeyBase64(),
    });
  }

  responseFailed(message) {
    return JSON.stringify({
      success: false,
      message,
    });
  }
}

export default EncryptedServer;
