<?php
ini_set('display_errors', 1);

header("Content-Type: application/json");
require_once "EncryptionServer.php";

$action = $_GET['action'] ?? null;

if (empty($action)) {
    echo responseFailed("No Action Found");
    exit;
}

try {
    $enc = new EncryptionServer();
    if($action == "token") {
        echo responseSuccess($enc->getPublicKey());
        exit;
    }

    $raw = file_get_contents("php://input");
    $payload = json_decode($raw, true);
    if (!$payload) {
        echo responseFailed("Invalid JSON input");
        exit;
    }
    $data = $payload['data'];
    list($encryptedData, $encryptedSessionKey) = explode('.', $data, 2);
    if (!$encryptedSessionKey || !$encryptedData) {
        echo responseFailed("Missing encrypted data");
        exit;
    }
    $sessionKey = $enc->decryptSessionKey($encryptedSessionKey);
    $decryptedData = $enc->decryptAES($encryptedData, $sessionKey);
    echo responseSuccess($enc->encryptAES($decryptedData, $sessionKey));
    exit;
} catch (Exception $e) {
    echo responseFailed($e->getMessage());
    exit;
}

function responseFailed($message) {
    return json_encode([
        "success" => false,
        "message" => $message
    ]);
}

function responseSuccess($data, $message = null) {
    $arr = [
        "success" => true,
        "token" => $data,
        "message" => $message
    ];
    if(empty($arr['message'])){
        unset($arr['message']);
    }
    return json_encode($arr);
}
