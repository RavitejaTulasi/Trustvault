import type {
  DocumentListParams,
  DocumentListResponse,
  DocumentResponse,
  DocumentUpdateRequest,
  GrantListResponse,
  GrantResponse,
  UserResponse,
} from './types';

/**
 * Empty default keeps the app same-origin: in dev, Vite proxies `/api` to the
 * backend so `SameSite=Lax` session/CSRF cookies are always attached by the
 * browser. For a cross-origin deployment set `VITE_API_BASE_URL` explicitly.
 */
export const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '';
export const CSRF_COOKIE_NAME = 'trustvault_csrf';
export const SESSION_BOOTSTRAP_PATH = '/api/v1/auth/me';

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('Network request failed. Check your connection and try again.');
    this.name = 'NetworkError';
    this.cause = cause;
  }
}

export function getCookie(name: string): string | undefined {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    const token = parts.pop()?.split(';').shift();
    return token ? decodeURIComponent(token) : undefined;
  }
  return undefined;
}

const CSRF_HEADER_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * The backend CSRF middleware sets the `trustvault_csrf` cookie on the response
 * of any request when the browser does not have one yet. A single harmless GET
 * is enough to bootstrap it. Never read `Set-Cookie` via JS: the cookie is
 * non-HttpOnly and lands in `document.cookie` on its own.
 */
async function bootstrapCsrfCookie(): Promise<void> {
  await fetch(`${BASE_URL}${SESSION_BOOTSTRAP_PATH}`, {
    method: 'GET',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  }).catch(() => undefined);
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const method = (options.method ?? 'GET').toUpperCase();
  const headers = new Headers(options.headers);

  // FormData bodies get their multipart boundary from the browser; a manually
  // set Content-Type would corrupt the upload, so only JSON bodies set it.
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
  if (options.body !== undefined && !isFormData && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  if (CSRF_HEADER_METHODS.has(method)) {
    let csrfToken = getCookie(CSRF_COOKIE_NAME);
    if (!csrfToken) {
      await bootstrapCsrfCookie();
      csrfToken = getCookie(CSRF_COOKIE_NAME);
    }
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  try {
    return await fetch(`${BASE_URL}${path}`, {
      ...options,
      method,
      credentials: 'include',
      headers,
    });
  } catch (err) {
    throw new NetworkError(err);
  }
}

/**
 * Parse an error body without assuming it is JSON. FastAPI normally returns
 * {"detail": "..."} but proxies or crashed servers can return plain text,
 * HTML, or nothing.
 */
async function toApiError(response: Response): Promise<ApiError> {
  let detail = `Request failed (HTTP ${response.status})`;
  try {
    const body: unknown = await response.json();
    if (
      body !== null &&
      typeof body === 'object' &&
      'detail' in body &&
      typeof (body as { detail: unknown }).detail === 'string'
    ) {
      detail = (body as { detail: string }).detail;
    }
  } catch {
    // keep the generic fallback detail
  }
  return new ApiError(response.status, detail);
}

export async function parseJsonResponse<T>(response: Response): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, 'Unexpected response format from server');
  }
}

export async function login(email: string, password: string): Promise<UserResponse> {
  const response = await apiFetch('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<UserResponse>(response);
}

/**
 * Resolve the current session from the session cookie.
 * - HTTP 401 → unauthenticated, resolves to null (not an error).
 * - Other failures (5xx, network) throw, so they stay distinguishable.
 */
export async function getMe(): Promise<UserResponse | null> {
  const response = await apiFetch('/api/v1/auth/me');
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<UserResponse>(response);
}

export async function logout(): Promise<void> {
  const response = await apiFetch('/api/v1/auth/logout', { method: 'POST' });
  if (!response.ok) {
    throw await toApiError(response);
  }
}

function buildQuery(params: DocumentListParams): string {
  const query = new URLSearchParams();
  const entries: Array<[string, string]> = [];
  if (params.page !== undefined) entries.push(['page', String(params.page)]);
  if (params.page_size !== undefined) entries.push(['page_size', String(params.page_size)]);
  const search = params.q?.trim() ?? '';
  if (search !== '') entries.push(['q', search]);
  const category = params.category?.trim() ?? '';
  if (category !== '') {
    entries.push(['category', category]);
  }
  if (params.created_from !== undefined && params.created_from !== '') {
    entries.push(['created_from', params.created_from]);
  }
  if (params.created_to !== undefined && params.created_to !== '') {
    entries.push(['created_to', params.created_to]);
  }
  for (const [key, value] of entries) {
    query.append(key, value);
  }
  const encoded = query.toString();
  return encoded === '' ? '' : `?${encoded}`;
}

export async function listDocuments(
  params: DocumentListParams = {},
): Promise<DocumentListResponse> {
  const response = await apiFetch(`/api/v1/documents${buildQuery(params)}`);
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<DocumentListResponse>(response);
}

export async function getDocument(id: string): Promise<DocumentResponse> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}`);
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<DocumentResponse>(response);
}

export async function uploadDocument(
  file: File,
  title: string,
  category?: string,
): Promise<DocumentResponse> {
  const form = new FormData();
  form.append('file', file);
  form.append('title', title);
  if (category !== undefined && category !== '') {
    form.append('category', category);
  }
  const response = await apiFetch('/api/v1/documents', { method: 'POST', body: form });
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<DocumentResponse>(response);
}

export async function updateDocument(
  id: string,
  changes: DocumentUpdateRequest,
): Promise<DocumentResponse> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(changes),
  });
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<DocumentResponse>(response);
}

export async function deleteDocument(id: string): Promise<void> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw await toApiError(response);
  }
}

/** Extract the server-suggested filename from a Content-Disposition header. */
export function parseContentDispositionFilename(header: string | null): string | undefined {
  if (header === null) {
    return undefined;
  }
  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (utf8Match) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      // fall through to the plain parameter
    }
  }
  const plainMatch = /filename=("([^"]+)"|[^;]+)/i.exec(header);
  if (plainMatch) {
    return plainMatch[2] ?? plainMatch[1];
  }
  return undefined;
}

/**
 * Download a document through the session cookie so the server records the
 * `document.download` audit event, then hand the bytes to the browser.
 */
export async function downloadDocument(id: string, fallbackName?: string): Promise<void> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}/download`);
  if (!response.ok) {
    throw await toApiError(response);
  }
  const blob = await response.blob();
  const filename =
    parseContentDispositionFilename(response.headers.get('Content-Disposition')) ??
    fallbackName ??
    'download';
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

export async function listGrants(id: string): Promise<GrantListResponse> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}/permissions`);
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<GrantListResponse>(response);
}

export async function createGrant(
  id: string,
  userId: string,
  permission: 'read' | 'edit',
): Promise<GrantResponse> {
  const response = await apiFetch(`/api/v1/documents/${encodeURIComponent(id)}/permissions`, {
    method: 'POST',
    body: JSON.stringify({ user_id: userId, permission }),
  });
  if (!response.ok) {
    throw await toApiError(response);
  }
  return parseJsonResponse<GrantResponse>(response);
}

export async function revokeGrant(id: string, userId: string): Promise<void> {
  const response = await apiFetch(
    `/api/v1/documents/${encodeURIComponent(id)}/permissions/${encodeURIComponent(userId)}`,
    { method: 'DELETE' },
  );
  if (!response.ok) {
    throw await toApiError(response);
  }
}
