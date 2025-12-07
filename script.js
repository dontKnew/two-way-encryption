// https://javascriptobfuscator.com/Javascript-Obfuscator.aspx
const EncryptedAPI = (() => {

    async function fetchPublicKey() {
        let pem = localStorage.getItem("token");
        if (!pem) {
            const res = await fetch("/api.php?action=token");
            const data = await res.json();
            pem = data.token;
            localStorage.setItem("token", pem);
        }
        return importRSAPublicKey(pem);
    }


    async function importRSAPublicKey(pem) {
        const b64 = pem.trim();
        const bin = atob(b64);
        const buf = Uint8Array.from(bin, c => c.charCodeAt(0));

        return await crypto.subtle.importKey(
            "spki",
            buf,
            { name: "RSA-OAEP", hash: "SHA-1" },
            false,
            ["encrypt"]
        );
    }

    async function generateAES() {
        return crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }


    async function aesEncrypt(key, json) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(json));
        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            encoded
        );

        const encryptedBytes = new Uint8Array(encrypted);
        const tag = encryptedBytes.slice(-16);       // last 16 bytes
        const ciphertext = encryptedBytes.slice(0, -16);

        // MATCH PHP FORMAT: iv + tag + ciphertext
        const combined = new Uint8Array(iv.length + tag.length + ciphertext.length);
        combined.set(iv, 0);
        combined.set(tag, iv.length);
        combined.set(ciphertext, iv.length + tag.length);

        return toBase64(combined);
    }

    async function encryptSessionKey(publicKey, aesKey) {
        const raw = await crypto.subtle.exportKey("raw", aesKey);
        const encrypted = await crypto.subtle.encrypt(
            { name: "RSA-OAEP", hash: "SHA-1" },
            publicKey,
            raw
        );
        return toBase64(encrypted);
    }

    async function decryptResponse(aesKey, base64Data) {
        const raw = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));

        const iv = raw.slice(0, 12);
        const tag = raw.slice(12, 28);
        const ciphertext = raw.slice(28);

        // WebCrypto expects ciphertext + tag at the end
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

    async function send(url, formData) {
        const publicKey = await fetchPublicKey();
        const aesKey = await generateAES();

        const encryptedData = await aesEncrypt(aesKey, formData);
        const encryptedSessionKey = await encryptSessionKey(publicKey, aesKey);
        const data = encryptedData + "." + encryptedSessionKey;

        const response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data })
        });
        const encryptedResp = await response.json();
        return await decryptResponse(aesKey, encryptedResp.token);
    }

    function toBase64(arrayBuffer) {
        let binary = "";
        const bytes = new Uint8Array(arrayBuffer);
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    return { send };

})();