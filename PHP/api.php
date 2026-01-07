<?php
ini_set('display_errors', 1);
header("Content-Type: application/json");

require_once "EncryptionServer.php";

$action = $_GET['action'] ?? null;
$enc = new EncryptionServer();

try {

    if($action=="update-token"){
        $enc->generatePublicPrivateKey();
        echo $enc->responseSuccessPlain([], "token update successfully");
        exit;
    }
    if($action === "token") {
        echo $enc->responsePublicKey();
        exit;
    }

    if($action === "verify-token") {
        $payload = json_decode(file_get_contents("php://input"), true);
        if (!$payload) {
            echo $enc->responseFailed("Invalid JSON");
            exit;
        }
        $enc->decryptResponse($payload);    

        echo $enc->responseSuccess(
            ["data" => $enc->decryptedData, 'success'=>true, 'message'=>"data fetch successfully"],
            "Token verified successfully"
        );
        exit;
    }
    echo $enc->responseFailed("Invalid action");
} catch (Exception $e) {
    echo $enc->responseFailed($e->getMessage());
}
