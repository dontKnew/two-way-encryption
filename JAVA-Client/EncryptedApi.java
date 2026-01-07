package com.rsdeveloper.johntv;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EncryptedAPI {

    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 16;

    private final Context context;
    private final String tokenKey;
    private final String tokenUrl;
    private final NetworkHelper networkHelper;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    /* ================= CALLBACK ================= */
    public interface Callback {
        void onSuccess(JSONObject result);
        void onError(String error);
    }

    /* ================= CONSTRUCTOR ================= */
    public EncryptedAPI(Context context, String tokenKey, String tokenUrl) {
        this.context = context;
        this.tokenKey = tokenKey;
        this.tokenUrl = tokenUrl;
        this.networkHelper = new NetworkHelper();
    }

    public EncryptedAPI(Context context) {
        this(context, "token", Helper.API_URL+"/token");
    }

    /* ================= PUBLIC ================= */
    public void send(String apiUrl, JSONObject jsonPayload, Callback callback) {

        fetchPublicKey(
                publicKey -> {
                    try {
                        SecretKey aesKey = generateAES();

                        String encryptedData = aesEncrypt(aesKey, jsonPayload);
                        String encryptedSessionKey = encryptSessionKey(publicKey, aesKey);

                        String token = encryptedData + "." + encryptedSessionKey;

                        JSONObject body = new JSONObject();
                        body.put("token", token);

                        networkHelper.makePostRequest(
                                apiUrl,
                                body,
                                new NetworkHelper.PostRequestCallback() {

                                    @Override
                                    public void onSuccess(String result) {
                                        try {
                                            JSONObject encryptedResp = new JSONObject(result);

                                            if (!encryptedResp.optBoolean("success", false)) {
                                                postError(callback,
                                                        encryptedResp.optString("message", "SERVER_ERROR"));
                                                return;
                                            }

                                            if (!encryptedResp.has("token")) {
                                                postError(callback, "INVALID_SERVER_RESPONSE");
                                                return;
                                            }

                                            JSONObject decrypted =
                                                    decryptResponse(aesKey, encryptedResp.getString("token"));

                                            postSuccess(callback, decrypted);

                                        } catch (Exception e) {
                                            postError(callback, e.getMessage());
                                        }
                                    }

                                    @Override
                                    public void onFailure(String error) {
                                        postError(callback, error);
                                    }
                                }
                        );

                    } catch (Exception e) {
                        postError(callback, e.getMessage());
                    }
                },
                error -> postError(callback, error)
        );
    }

    /* ================= UI THREAD HELPERS ================= */
    private void postSuccess(Callback callback, JSONObject data) {
        uiHandler.post(() -> callback.onSuccess(data));
    }

    private void postError(Callback callback, String error) {
        uiHandler.post(() -> callback.onError(error));
    }

    /* ================= PUBLIC KEY ================= */

    private void fetchPublicKey(PublicKeyCallback success, ErrorCallback error) {

        SessionHelper session = new SessionHelper(context);
        String cachedKey = session.getString(tokenKey, null);
        if (cachedKey != null) {
            try {
                success.onSuccess(importRSAPublicKey(cachedKey));
            } catch (Exception e) {
                session.removeKey(tokenKey);
                error.onError("PUBLIC_KEY_IMPORT_FAILED");
            }
            return;
        }

        JSONObject jsoBlank = new JSONObject();
        networkHelper.makePostRequest(
                tokenUrl,
                jsoBlank,
                new NetworkHelper.PostRequestCallback() {

                    @Override
                    public void onSuccess(String result) {
                        try {
                            JSONObject res = new JSONObject(result);

                            if (!res.optBoolean("success", false) || !res.has("token")) {
                                error.onError("INVALID_PUBLIC_KEY_RESPONSE");
                                return;
                            }

                            String pem = res.getString("token");
                            session.saveString(tokenKey, pem);
                            success.onSuccess(importRSAPublicKey(pem));

                        } catch (Exception e) {
                            error.onError(e.getMessage());
                        }
                    }

                    @Override
                    public void onFailure(String err) {
                        error.onError(err);
                    }
                }
        );
    }

    /* ================= RSA ================= */

    private PublicKey importRSAPublicKey(String pem) throws Exception {
        byte[] decoded = Base64.decode(pem.trim(), Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private String encryptSessionKey(PublicKey publicKey, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(aesKey.getEncoded());
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    /* ================= AES ================= */

    private SecretKey generateAES() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(AES_KEY_SIZE);
        return gen.generateKey();
    }

    private String aesEncrypt(SecretKey key, JSONObject json) throws Exception {

        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

        byte[] encrypted = cipher.doFinal(
                json.toString().getBytes(StandardCharsets.UTF_8)
        );

        byte[] ciphertext = new byte[encrypted.length - TAG_SIZE];
        byte[] tag = new byte[TAG_SIZE];

        System.arraycopy(encrypted, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(encrypted, ciphertext.length, tag, 0, TAG_SIZE);

        byte[] combined = new byte[iv.length + tag.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(tag, 0, combined, iv.length, tag.length);
        System.arraycopy(ciphertext, 0, combined, iv.length + tag.length, ciphertext.length);

        return Base64.encodeToString(combined, Base64.NO_WRAP);
    }

    private JSONObject decryptResponse(SecretKey aesKey, String base64Data) throws Exception {

        byte[] raw = Base64.decode(base64Data, Base64.DEFAULT);

        byte[] iv = new byte[IV_SIZE];
        byte[] tag = new byte[TAG_SIZE];
        byte[] ciphertext = new byte[raw.length - IV_SIZE - TAG_SIZE];

        System.arraycopy(raw, 0, iv, 0, IV_SIZE);
        System.arraycopy(raw, IV_SIZE, tag, 0, TAG_SIZE);
        System.arraycopy(raw, IV_SIZE + TAG_SIZE, ciphertext, 0, ciphertext.length);

        byte[] ctWithTag = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, ctWithTag, 0, ciphertext.length);
        System.arraycopy(tag, 0, ctWithTag, ciphertext.length, tag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] decrypted = cipher.doFinal(ctWithTag);
        return new JSONObject(new String(decrypted, StandardCharsets.UTF_8));
    }

    /* ================= INTERNAL CALLBACKS ================= */

    private interface PublicKeyCallback {
        void onSuccess(PublicKey key);
    }

    private interface ErrorCallback {
        void onError(String error);
    }
}


// ✅ ON ACTIVITY/ AND BACKGROUND SAME CODE..
//EncryptedAPI api = new EncryptedAPI(this);
//
//JSONObject payload = new JSONObject();
//payload.put("email", "test@test.com");
//
//api.send(
//    "https://example.com/api.php?action=verify-token",
//    payload,
//    new EncryptedAPI.Callback() {
//
//    @Override
//    public void onSuccess(JSONObject result) {
//        // 🟢 UI THREAD
//        textView.setText(result.toString());
//        Toast.makeText(MainActivity.this, "Success", Toast.LENGTH_SHORT).show();
//    }
//
//    @Override
//    public void onError(String error) {
//        // 🟢 UI THREAD
//        Toast.makeText(MainActivity.this, error, Toast.LENGTH_LONG).show();
//    }
//}
//);
