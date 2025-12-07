<?php

class EncryptionServer
{
    private $privateKeyPath;
    private $publicKeyPath;
    private string $privateKey;
    private string $publicKey;
    private string $algo_method = "aes-256-gcm";

    public function __construct(string $privateKeyPath = null, string $publicKeyPath = null)
    {
        $this->privateKeyPath = $privateKeyPath;
        $this->publicKeyPath  = $publicKeyPath;
        $this->privateKey = @file_get_contents($privateKeyPath ?? "private.pem");
        $this->publicKey  = @file_get_contents($publicKeyPath ?? "public.pem");

        $this->throwIfFalse($this->privateKey, "Private key file not found or unreadable.");
        $this->throwIfFalse($this->publicKey,  "Public key file not found or unreadable.");
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /** ENCRYPT SESSION KEY (RSA) */
    public function encryptSessionKey(string $sessionKey): string
    {
        $publicKey = openssl_pkey_get_public($this->publicKey);
        $this->throwIfFalse($publicKey, "Invalid RSA public key.");

        $ok = openssl_public_encrypt(
            $sessionKey,
            $encryptedKey,
            $publicKey,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        $this->throwIfFalse($ok, "RSA encryption failed.");

        return base64_encode($encryptedKey);
    }

    /** DECRYPT SESSION KEY (RSA) */
    public function decryptSessionKey(string $encrypted): string
    {
        $encryptedBin = base64_decode($encrypted, true);
        $this->throwIfFalse($encryptedBin, "Base64 decode failed for encrypted session key.");

        $privateKey = openssl_pkey_get_private($this->privateKey);
        $this->throwIfFalse($privateKey, "Invalid RSA private key.");

        $ok = openssl_private_decrypt(
            $encryptedBin,
            $sessionKeyRaw,
            $privateKey,
            OPENSSL_PKCS1_OAEP_PADDING
        );

        $this->throwIfFalse($ok, "RSA session key decryption failed.");

        return $sessionKeyRaw;
    }

    /** DECRYPT CLIENT PAYLOAD */
    public function decryptAES(string $encryptedData, string $sessionKey): array
    {
        $raw = base64_decode($encryptedData);
        $iv  = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext  = substr($raw, 28); 

        $json = openssl_decrypt(
            $ciphertext,
            "aes-256-gcm",
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $this->throwIfFalse($json, "AES-GCM decryption failed.");

        $decoded = json_decode($json, true);
        $this->throwIfFalse($decoded !== null, "JSON decode failed.");
        return $decoded;
    }


    /** ENCRYPT SERVER RESPONSE */
   public function encryptAES(array $payload, string $sessionKey): string
    {
        $json = json_encode($payload);

        $iv = random_bytes(12);

        $encrypted = openssl_encrypt(
            $json,
            "aes-256-gcm",
            $sessionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        return base64_encode($iv . $tag . $encrypted);
    }



    /** CENTRALIZED ERROR HANDLER */
    private function throwIfFalse($condition, string $message)
    {
        if (!$condition) {
            $error = openssl_error_string();
            if ($error) {
                throw new Exception("$message (OpenSSL: $error)");
            }
            throw new Exception($message);
        }
    }

    public function getAESKey(){
        return random_bytes(32);
    }

    public function generatePublicPrivateKey(){
        $keys = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keys, $privateKey);
        $publicKey = openssl_pkey_get_details($keys)["key"];

        file_put_contents($this->privateKeyPath, $privateKey);
        file_put_contents($this->publicKeyPath, $publicKey);
    }
}



/* Example 
<?php
ini_set('display_errors', 1);
require_once "EncryptionServer.php";

try {
    $enc = new EncryptionServer();
    $key = $enc->getAESKey();
    $encrypted = $enc->encryptAES(['sajid', 'krishan', 'aman'], $key);
    $decrypted = $enc->decryptAES($encrypted, $key);
} catch(Exception $e) {
    echo $e->getMessage();
}
*/