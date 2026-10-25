import {
  register as apiRegister,
  changePassword as apiChangePassword,
  requestPasswordReset as apiRequestPasswordReset,
  verifyPasswordResetOtp as apiVerifyPasswordResetOtp,
  confirmPasswordReset as apiConfirmPasswordReset,
  updateMe as apiUpdateMe,
  login as apiLogin,
  getDemoAccounts as apiGetDemoAccounts,
  getMe as apiGetMe,
  logout as apiLogout,
  listDocuments as apiListDocuments,
  getDocument as apiGetDocument,
  uploadDocument as apiUploadDocument,
  updateDocument as apiUpdateDocument,
  deleteDocument as apiDeleteDocument,
  downloadDocument as apiDownloadDocument,
  listGrants as apiListGrants,
  resolveGrantRecipient as apiResolveGrantRecipient,
  createGrant as apiCreateGrant,
  revokeGrant as apiRevokeGrant,
  getPermissionRequestStatus as apiGetPermissionRequestStatus,
  createPermissionRequest as apiCreatePermissionRequest,
  listPendingPermissionRequests as apiListPendingPermissionRequests,
  updatePermissionRequestStatus as apiUpdatePermissionRequestStatus,
  getDocumentActivity as apiGetDocumentActivity,
  exportDocumentActivity as apiExportDocumentActivity,
} from './api';
import type {
  AuditEventListResponse,
  DemoAccount,
  DocumentListParams,
  DocumentListResponse,
  DocumentResponse,
  DocumentUpdateRequest,
  GrantListResponse,
  GrantRecipientLookupResponse,
  GrantResponse,
  PermissionRequestResponse,
  UserResponse,
  UserUpdateRequest,
} from './types';

export async function register(
  fullName: string,
  email: string,
  password: string,
): Promise<UserResponse> {
  return apiRegister(fullName, email, password);
}

export async function updateMe(changes: UserUpdateRequest): Promise<UserResponse> {
  return apiUpdateMe(changes);
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<UserResponse> {
  return apiChangePassword(currentPassword, newPassword);
}

export async function requestPasswordReset(email: string): Promise<string> {
  return apiRequestPasswordReset(email);
}

export async function verifyPasswordResetOtp(
  email: string,
  otpCode: string,
): Promise<void> {
  return apiVerifyPasswordResetOtp(email, otpCode);
}

export async function confirmPasswordReset(
  email: string,
  otpCode: string,
  newPassword: string,
): Promise<string> {
  return apiConfirmPasswordReset(email, otpCode, newPassword);
}

export async function login(email: string, password: string): Promise<UserResponse> {
  return apiLogin(email, password);
}

export async function getDemoAccounts(): Promise<DemoAccount[]> {
  return apiGetDemoAccounts();
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
  idempotencyKey: string,
  category?: string,
): Promise<DocumentResponse> {
  return apiUploadDocument(file, title, idempotencyKey, category);
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

export async function resolveGrantRecipient(
  id: string,
  email: string,
): Promise<GrantRecipientLookupResponse> {
  return apiResolveGrantRecipient(id, email);
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

export async function getPermissionRequestStatus(
  documentId: string,
): Promise<PermissionRequestResponse | null> {
  return apiGetPermissionRequestStatus(documentId);
}

export async function createPermissionRequest(
  documentId: string,
  requestedRole: string = 'download_activity',
): Promise<PermissionRequestResponse> {
  return apiCreatePermissionRequest(documentId, requestedRole);
}

export async function listPendingPermissionRequests(
  documentId?: string,
): Promise<PermissionRequestResponse[]> {
  return apiListPendingPermissionRequests(documentId);
}

export async function updatePermissionRequestStatus(
  requestId: number,
  status: 'approved' | 'rejected' | 'canceled',
): Promise<PermissionRequestResponse> {
  return apiUpdatePermissionRequestStatus(requestId, status);
}

export async function getDocumentActivity(
  documentId: string,
  page: number = 1,
  pageSize: number = 25,
): Promise<AuditEventListResponse> {
  return apiGetDocumentActivity(documentId, page, pageSize);
}

export async function exportDocumentActivity(
  documentId: string,
  format: 'csv' | 'excel' = 'csv',
): Promise<void> {
  return apiExportDocumentActivity(documentId, format);
}
