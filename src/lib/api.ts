import type { RbacRole } from '../types/aegis';

let currentRole: RbacRole = 'admin';

export function setApiRole(role: RbacRole) {
  currentRole = role;
}

export function getApiRole(): RbacRole {
  return currentRole;
}

export async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set('X-Aegis-Role', currentRole);
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}
