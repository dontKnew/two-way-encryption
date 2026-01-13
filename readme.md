# Two Way Encryption
## Encryption Information
### ClientSide 
1. const publicKey = await this.fetchPublicKey();
2. const aesKey = await this.generateAesKey();    // Does it Return String ??
3. const encryptedDataByAesKey = await this.aesEncrypt(aesKey, jsonPayload);
4. const encryptedAesKey = await this.encryptAesKey(publicKey, aesKey);
5. const data = encryptedDataByAesKey + "." + encryptedAesKey;
6. const clientBody = JSON.stringify({ token: data });

### ServerSide
1. const privateKey = "";
2. const publicKey = "";
3. const clientBody = JSON.parse(clientBody);
4. const [encryptedDataByAesKey, encryptedAesKey] = clientBody.token.split(".", 2);
5. const aesKey = this.decryptAesKey(encryptedAesKey, privateKey);
6. const jsonPayload = aesDecrypt(asKey, encryptedDataByAesKey);
// LogicProcess payload = {success:true, data:{name:"sajid", "email":"sajid@gmail.com"}}
7. const serverBody = encryptResponse(aesKey, payload)
