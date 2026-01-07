import ApiHandler from "@/lib/ApiHandler";
export async function POST() {
  const api = new ApiHandler();
  return api.responsePublicKey();
}
