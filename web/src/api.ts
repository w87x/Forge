export type ApiError = { code: string; message: string; correlation_id: string };

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const method = (init?.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = document.cookie.split('; ').find((item) => item.startsWith('forge_csrf='))?.slice('forge_csrf='.length);
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf));
  }
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = ((await response.json()) as ApiError).message || message; } catch { /* Non-JSON upstream response. */ }
    if (response.status === 429 && response.headers.get('Retry-After')) message += ` (retry after ${response.headers.get('Retry-After')} seconds)`;
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
