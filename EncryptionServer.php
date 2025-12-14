<?php

class EncryptionServer
{
    public array $decryptedData;
    private string $sessionKey;
    private string $privateKey;
    private string $publicKey;

    public function __construct(
        string $privateKeyPath = "private.pem",
        string $publicKeyPath = "public.pem"
    ) {
        $this->privateKey = @file_get_contents($privateKeyPath);
        $this->publicKey  = @file_get_contents($publicKeyPath);
    }

    /* ================= PUBLIC KEY ================= */
    public function getPublicKeyBase64(): string
    {
        $clean = preg_replace('/-----(BEGIN|END) PUBLIC KEY-----|\s/', '', $this->publicKey);
        return $clean;
    }

    /* ================= RSA ================= */
    public function decryptSessionKey(string $encrypted): string
    {
        $bin = base64_decode($encrypted, true);
        $this->throwIfFalse($bin, "Invalid base64 session key");

        $priv = openssl_pkey_get_private($this->privateKey);
        $this->throwIfFalse($priv, "Invalid private key");

        $ok = openssl_private_decrypt(
            $bin,
            $sessionKey,
            $priv,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        $this->throwIfFalse($ok, "RSA decrypt failed");
        return $sessionKey;
    }

    /* ================= AES ================= */
    public function decryptAES(string $encryptedData, string $sessionKey): array
    {
        $raw = base64_decode($encryptedData, true);
        $this->throwIfFalse($raw, "Invalid base64 payload");

        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $json = openssl_decrypt(
            $ciphertext,
            "aes-256-gcm",
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $this->throwIfFalse($json, "AES decrypt failed");

        $data = json_decode($json, true);
        $this->throwIfFalse(is_array($data), "JSON decode failed");

        return $data;
    }

    public function encryptAES(array $payload, string $sessionKey): string
    {
        $iv = random_bytes(12);

        $ciphertext = openssl_encrypt(
            json_encode($payload),
            "aes-256-gcm",
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return base64_encode($iv . $tag . $ciphertext);
    }


/* ================= KEY GENERATION ================= */
public function generatePublicPrivateKey(
    string $privateKeyPath = "private.pem",
    string $publicKeyPath  = "public.pem",
    int $bits = 2048
): bool {
    $config = [
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
        "private_key_bits" => $bits,
    ];

    $res = openssl_pkey_new($config);
    if ($res === false) {
        throw new Exception("Invalid token format");
    }

    // Export private key
    $ok = openssl_pkey_export($res, $privateKey);
    if (!$ok || empty($privateKey)) {
        throw new Exception("Invalid token format");
    }

    // Get public key
    $details = openssl_pkey_get_details($res);
    if ($details === false || empty($details['key'])) {
        throw new Exception("Invalid token format");
    }

    $publicKey = $details['key'];

    // Save keys
    if (file_put_contents($privateKeyPath, $privateKey) === false) {
        throw new Exception("Invalid token format");
    }

    if (file_put_contents($publicKeyPath, $publicKey) === false) {
        throw new Exception("Invalid token format");
    }

    // Secure permissions
    @chmod($privateKeyPath, 0600);
    @chmod($publicKeyPath, 0644);

    return true;
}


    /* ================= CLIENT REQUEST ================= */
    public function decryptResponse(array $payload): array
    {
        $this->throwIfFalse(!empty($payload['token']), "Token missing");

        if (!str_contains($payload['token'], '.')) {
            throw new Exception("Invalid token format");
        }

        [$encryptedData, $encryptedSessionKey] = explode('.', $payload['token'], 2);

        $this->sessionKey = $this->decryptSessionKey($encryptedSessionKey);
        $this->decryptedData = $this->decryptAES($encryptedData, $this->sessionKey);
        return $this->decryptedData;
    }

    /* ================= RESPONSES ================= */

    public function responseSuccess(array $payload, string $message = null): string
    {
        $token = $this->encryptAES($payload, $this->sessionKey);

        $res = ["success" => true, "token" => $token];
        if ($message) $res["message"] = $message;

        return json_encode($res);
    }

    public function responseSuccessPlain(array $payload, string $message = null): string
    {

        $res = ["success" => true, "data" => $payload];
        if ($message) $res["message"] = $message;

        return json_encode($res);
    }

    public function responsePublicKey(): string
    {
        return json_encode([
            "success" => true,
            "token" => $this->getPublicKeyBase64()
        ]);
    }

    public function responseFailed(string $message): string
    {
        return json_encode(["success" => false, "message" => $message]);
    }

    /* ================= UTIL ================= */

    private function throwIfFalse($cond, string $msg): void
    {
        if (!$cond) {
            throw new Exception($msg);
        }
    }
}
