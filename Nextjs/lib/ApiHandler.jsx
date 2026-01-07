import EncryptedServer from "@/lib/EncryptedServer";
import { NextResponse } from "next/server";

class ApiHandler {

  constructor(req=null) {
    this.req = req;
    this.server = new EncryptedServer();
    this.data = null;
    this.EncryptionMode = process.env.HAS_API_ENCRYPTED === "true";
  }

  async request(){
    if(this.EncryptionMode){
        return await this.decryptRequest();
      }
    return await this.req.json();
  }

  async decryptRequest() {
    const payload = await this.req.json();
    if (!payload?.token) {
       throw new Error("Encrypted token missing");
    }
    this.data = this.server.decryptResponse(payload);
    return this.data;
  }

  /* ================= RESPONSE ================= */
  // Encrypted Success
  response(payload, message=null){
    if(this.EncryptionMode){
      this.data = this.server.responseSuccess(payload, message);
      return this._nextResponse();
    }else {
      return this.responsePlain(payload, message);
    }
  }

  // Encrypted Success Plain
  responsePlain(payload, message = null) {
    this.data = this.server.responseSuccessPlain(payload, message);
    return this._nextResponse();
  }
  
  // Encrypted Failed Plain
  responseFailPlain(message = null) {
    this.data = this.server.responseFailed(message);
    return this._nextResponse();
  }

  responsePublicKey(){
    this.data = this.server.responsePublicKey();
    return this._nextResponse()
  }

  _nextResponse(){ // private
    return new NextResponse(
      this.data,
      { headers: { "Content-Type": "application/json" } }
    );
  }
}

export default ApiHandler;
