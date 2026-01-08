# Two Way Encryption
## Encryption Information
### ClientSide 
const publicKey = await this.fetchPublicKey();
const aesKey = await this.generateAesKey();    // Does it Return String ??
const encryptedDataByAesKey = await this.aesEncrypt(aesKey, jsonPayload);
const encryptedAesKey = await this.encryptAesKey(publicKey, aesKey);
const data = encryptedDataByAesKey + "." + encryptedAesKey;
const clientBody = JSON.stringify({ token: data });

### ServerSide
const privateKey = "";
const publicKey = "";
const clientBody = JSON.parse(clientBody);
const [encryptedDataByAesKey, encryptedAesKey] = clientBody.token.split(".", 2);
const aesKey = this.decryptAesKey(encryptedAesKey, privateKey);
const jsonPayload = aesDecrypt(asKey, encryptedDataByAesKey);
// LogicProcess payload = {success:true, data:{name:"sajid", "email":"sajid@gmail.com"}}
const serverBody = encryptResponse(aesKey, payload)
