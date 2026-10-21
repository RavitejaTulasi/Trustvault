import {
  login as apiLogin,
  getMe as apiGetMe,
  logout as apiLogout,
  listDocuments as apiListDocuments,
  getDocument as apiGetDocument,
  uploadDocument as apiUploadDocument,
  updateDocument as apiUpdateDocument,
  deleteDocument as apiDeleteDocument,
  downloadDocument as apiDownloadDocument,
  listGrants as apiListGrants,
  createGrant as apiCreateGrant,
  revokeGrant as apiRevokeGrant,
} from './api';
import type {
  DocumentListParams,
  DocumentListResponse,
  DocumentResponse,
  DocumentUpdateRequest,
  GrantListResponse,
  GrantResponse,
  UserResponse,
} from './types';

export async function login(email: string, password: string): Promise<UserResponse> {
  return apiLogin(email, password);
}

export async function getMe(): Promise<UserResponse | null> {
  return apiGetMe();
}

export async function logout(): Promise<void> {
  return apiLogout();
}

export async function listDocuments(
  params: DocumentListParams = {},
): Promise<DocumentListResponse> {
  return apiListDocuments(params);
}

export async function getDocument(id: string): Promise<DocumentResponse> {
  return apiGetDocument(id);
}

export async function uploadDocument(
  file: File,
  title: string,
  category?: string,
): Promise<DocumentResponse> {
  return apiUploadDocument(file, title, category);
}

export async function updateDocument(
  id: string,
  changes: DocumentUpdateRequest,
): Promise<DocumentResponse> {
  return apiUpdateDocument(id, changes);
}

export async function deleteDocument(id: string): Promise<void> {
  return apiDeleteDocument(id);
}

export async function downloadDocument(id: string, fallbackName?: string): Promise<void> {
  return apiDownloadDocument(id, fallbackName);
}

export async function listGrants(id: string): Promise<GrantListResponse> {
  return apiListGrants(id);
}

export async function createGrant(
  id: string,
  userId: string,
  permission: 'read' | 'edit',
): Promise<GrantResponse> {
  return apiCreateGrant(id, userId, permission);
}

export async function revokeGrant(id: string, userId: string): Promise<void> {
  return apiRevokeGrant(id, userId);
}
