// Silo's plugin proxy authenticates each request via a Bearer token
// (Authorization header) or ?token= query param. The SPA receives the token
// on its initial load via URL ?token= (set by the sidebar link). We capture
// it once into memory for use on all subsequent fetches.
// Theme is also captured here so semantic Tailwind classes pick up the
// active silo theme.

import { api } from "./api";

let cachedToken: string | null = null;
let cachedTheme: string | null = null;

export type Identity = {
  user_id: string;
  role: string;
  theme: string;
};

let currentIdentity: Identity | null = null;

export function captureFromURL(params: URLSearchParams): void {
  const t = params.get("token");
  if (t) cachedToken = t;

  const th = params.get("theme") ?? sessionStorage.getItem("silo-theme");
  if (th) {
    cachedTheme = th;
    sessionStorage.setItem("silo-theme", th);
  }
}

export function getCachedToken(): string | null {
  return cachedToken;
}

export function getCachedTheme(): string | null {
  return cachedTheme;
}

export async function loadIdentity(): Promise<Identity | null> {
  try {
    currentIdentity = await api.get<Identity>("/api/v1/admin/whoami");
    if (currentIdentity?.theme && !cachedTheme) {
      cachedTheme = currentIdentity.theme;
      sessionStorage.setItem("silo-theme", currentIdentity.theme);
      document.documentElement.dataset.theme = currentIdentity.theme;
    }
    return currentIdentity;
  } catch {
    currentIdentity = null;
    return null;
  }
}

export function currentUser(): (Identity & { isAdmin: boolean }) | null {
  if (!currentIdentity) return null;
  return { ...currentIdentity, isAdmin: currentIdentity.role === "admin" };
}

export function installID(): string {
  const m = window.location.pathname.match(/^\/api\/v1\/plugins\/(\d+)/);
  return m ? m[1] : "";
}

// Exposed for tests only.
export function _resetForTest(): void {
  cachedToken = null;
  cachedTheme = null;
  currentIdentity = null;
}
