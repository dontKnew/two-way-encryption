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
