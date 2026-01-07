"use client";

import { useState, useCallback } from "react";
import ApiRequest from "@/lib/ApiRequest";

export default function useApiRequest() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const send = useCallback(async (url, payload) => {
    setLoading(true);
    setError(null);

    try {
      const api = new ApiRequest();
      const response = await api.send(url, payload);
      setData(response.data);
      return response;
    } catch (err) {
      const message = err?.message || "UNKNOWN_ERROR";
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    send,
    data,
    error,
    loading,
  };
}
