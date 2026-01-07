import EncryptedServer from "@/lib/EncryptedServer";
import { NextResponse } from "next/server";
export async function GET(req) {
  let serverEncryptedResponse;
  let serverDecryptedResponse;
  let decryptRespose;

  let aesKey;
  let jsonPayload;
  let encryptedDataByAesKey;
  let encryptedAesKey;
  let clientBody;
  let decryptedAesKey;
  let decryptedDataByAesKey;
  const server = new EncryptedServer();
  try {
    // const aesKey = await server.generateAesKey();
    // const jsonPayload = ['1', '2', '3', '4', '5'];
    // const encryptedDataByAesKey = server.encryptAes(jsonPayload, aesKey);    
    // const encryptedAesKey = server.encryptAesKey(aesKey);
    // const data = encryptedDataByAesKey + "." + encryptedAesKey;
    // const clientBody = { token: data };

    // const decryptRespose = server.decryptResponse(clientBody);

    // const decryptedAesKey = server.decryptAesKey(encryptedAesKey);
    // const decryptedDataByAesKey = server.decryptAes(encryptedDataByAesKey, decryptedAesKey);

    // const serverEncryptedJsonResponse = server.responseSuccess(jsonPayload, "server Response Encrypted");
    // const serverEncryptedResponse = JSON.parse(serverEncryptedJsonResponse);
    // const serverDecryptedResponse = server.decryptAes(serverEncryptedResponse.token, aesKey);

    return NextResponse.json({
        success: true,

        serverEncryptedResponse: serverEncryptedResponse ?? null,
        serverDecryptedResponse: serverDecryptedResponse ?? null,
        decryptRespose: decryptRespose ?? null,

        aesKey: aesKey ?? null,
        jsonPayload: jsonPayload ?? null,

        encryptedDataByAesKey: encryptedDataByAesKey ?? null,
        encryptedAesKey: encryptedAesKey ?? null,

        clientBody: clientBody ?? null,

        decryptedAesKey: decryptedAesKey ?? null,
        decryptedDataByAesKey: decryptedDataByAesKey ?? null,
      });

  } catch (err) {
    return NextResponse.json({success:false, message:err.message})
  }
}
