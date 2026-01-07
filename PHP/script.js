class EncryptedAPI {

    constructor(options = {}) {
        this.tokenKey = options.tokenKey || "token";
        this.tokenUrl = options.tokenUrl || "https://johntv.live/api/v1/token";
    }

    /* ================= PUBLIC ================= */

    async send(url, jsonPayload) {
        try {
            const publicKey = await this.fetchPublicKey();
            const aesKey = await this.generateAES();    

            const encryptedData = await this.aesEncrypt(aesKey, jsonPayload);
            const encryptedSessionKey = await this.encryptSessionKey(publicKey, aesKey);

            const data = encryptedData + "." + encryptedSessionKey;

            const response = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token: data })
            });

            if (!response.ok) {
                throw new Error(`HTTP_ERROR_${response.status}`);
            }

            const encryptedResp = await response.json();

            if (!encryptedResp || encryptedResp.success !== true) {
                throw new Error(
                    encryptedResp?.message || "SERVER_ERROR"
                );
            }

            if (!encryptedResp.token) {
                throw new Error("INVALID_SERVER_RESPONSE");
            }

            return await this.decryptResponse(aesKey, encryptedResp.token);

        } catch (err) {
            throw err; // rethrow for caller
        }
    }

    /* ================= KEY HANDLING ================= */

    async fetchPublicKey() {
        try {
            let pem = localStorage.getItem(this.tokenKey);

            if (!pem) {
                const res = await fetch(this.tokenUrl, {
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
                localStorage.setItem(this.tokenKey, pem);
            }

            return await this.importRSAPublicKey(pem);

        } catch (err) {
            console.error("fetchPublicKey error:", err);
            localStorage.removeItem(this.tokenKey); // cleanup bad key
            throw err;
        }
    }

    async importRSAPublicKey(pem) {
        try {
            const bin = atob(pem.trim());
            const buf = Uint8Array.from(bin, c => c.charCodeAt(0));

            return await crypto.subtle.importKey(
                "spki",
                buf,
                { name: "RSA-OAEP", hash: "SHA-1" },
                false,
                ["encrypt"]
            );
        } catch (err) {
            throw new Error("PUBLIC_KEY_IMPORT_FAILED");
        }
    }

    async generateAES() {
        try {
            return await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
        } catch (err) {
            throw new Error("AES_KEY_GENERATION_FAILED");
        }
    }

    /* ================= AES ================= */

    async aesEncrypt(key, json) {
        try {
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

            return this.toBase64(combined);

        } catch (err) {
            throw new Error("AES_ENCRYPTION_FAILED");
        }
    }

    async decryptResponse(aesKey, base64Data) {
        try {
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

        } catch (err) {
            throw new Error("AES_DECRYPTION_FAILED");
        }
    }

    /* ================= RSA ================= */

    async encryptSessionKey(publicKey, aesKey) {
        try {
            const raw = await crypto.subtle.exportKey("raw", aesKey);

            const encrypted = await crypto.subtle.encrypt(
                { name: "RSA-OAEP", hash: "SHA-1" },
                publicKey,
                raw
            );

            return this.toBase64(encrypted);

        } catch (err) {
            throw new Error("RSA_ENCRYPTION_FAILED");
        }
    }

    /* ================= UTIL ================= */

    toBase64(buffer) {
        let binary = "";
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
}
