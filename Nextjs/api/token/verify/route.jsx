import ApiHandler from "@/lib/ApiHandler";
export async function POST(req) {
  const api = new ApiHandler(req);
  try {
    const data = await api.request();
    return api.response(
      { success: true, payload: data },
      "Token Verified"
    );
  } catch (err) {
    
    return api.responseFailPlain(err.message);
  }
}
