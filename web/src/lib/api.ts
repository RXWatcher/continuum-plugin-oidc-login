// Thin fetch wrapper that knows how to talk to the plugin's HTTP routes
// mounted under /api/v1/plugins/{installId}/...

import { getCachedToken } from "./identity";

export function mountPath(): string {
  // The plugin SPA is served under /api/v1/plugins/{installationId}/admin/...
  // We derive the prefix at runtime since the install ID is host-assigned.
  const m = window.location.pathname.match(/^(\/api\/v1\/plugins\/\d+)/);
  return m ? m[1] : "";
}

export function installationID(): number | null {
  const m = mountPath().match(/\/api\/v1\/plugins\/(\d+)$/);
  if (!m?.[1]) return null;
  const id = Number(m[1]);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function authHeaders(): Record<string, string> {
  const t = getCachedToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function jsonOrThrow<T>(r: Response): Promise<T> {
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`${r.status}: ${body}`);
  }
  if (r.status === 204) return undefined as T;
  const text = await r.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export const api = {
  get: <T>(path: string): Promise<T> =>
    fetch(mountPath() + path, { headers: authHeaders() }).then(jsonOrThrow<T>),
  post: <T>(path: string, body: unknown): Promise<T> =>
    fetch(mountPath() + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<T>),
  patch: <T>(path: string, body: unknown): Promise<T> =>
    fetch(mountPath() + path, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<T>),
  hostPut: <T>(path: string, body: unknown): Promise<T> =>
    fetch(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    }).then(jsonOrThrow<T>),
  delete: <T>(path: string): Promise<T> =>
    fetch(mountPath() + path, {
      method: "DELETE",
      headers: authHeaders(),
    }).then(jsonOrThrow<T>),
};
