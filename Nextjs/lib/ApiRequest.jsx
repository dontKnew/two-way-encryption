import EncryptedClient from "./EncryptedClient";

class ApiRequest {
  /* ================= PRIVATE FIELDS ================= */
  #apiUrl;
  #encryptionMode;
  #client;
  #path;
  #payload;

  /* ================= CONSTRUCTOR ================= */
  constructor() {
    this.#apiUrl = process.env.NEXT_PUBLIC_API_URL;
    this.#encryptionMode = process.env.NEXT_PUBLIC_HAS_API_ENCRYPTED === "true";
    this.#client = new EncryptedClient();

    this.#path = null;
    this.#payload = null;
  }

  /* ================= PUBLIC API ================= */
  async send(path, payload) {
    this.#path = path;
    this.#payload = payload;
    if (this.#encryptionMode) {
      return this.#encryptedSend();
    }

    return this.#plainSend();
  }

  /* ================= PRIVATE METHODS ================= */

  async #encryptedSend() {
    try {
      return await this.#client.send(
        this.#path,
        this.#payload
      );
    } catch (e) {
      throw e;
    }
  }

  async #plainSend() {
    try {
      const response = await fetch(this.#apiUrl + this.#path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(this.#payload),
      });
      if (!response.ok) {
        throw new Error(`HTTP_ERROR_${response.status}`);
      }
      const responseJson = await response.json();
      if(!responseJson.data){
        throw new Error(responseJson.message || "Data not found");
      }
       return responseJson.data; 
    } catch (err) {
      throw err;
    }
  }
}

export default ApiRequest;
