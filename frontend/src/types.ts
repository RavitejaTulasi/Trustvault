export interface UserResponse {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export type Role = 'admin' | 'owner' | 'viewer';

export type EffectivePermission = 'owner' | 'edit' | 'read';

export interface DocumentResponse {
  id: string;
  title: string;
  original_filename: string;
  file_size_bytes: number;
  mime_type: string;
  category: string;
  owner_id: string;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
}

export interface DocumentListItem extends DocumentResponse {
  effective_permission: EffectivePermission;
}

export interface DocumentListResponse {
  documents: DocumentListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface DocumentUpdateRequest {
  title?: string;
  category?: string;
}

export interface GrantResponse {
  id: string;
  document_id: string;
  user_id: string;
  permission: 'read' | 'edit';
  granted_by_id: string | null;
  is_revoked: boolean;
  created_at: string;
  updated_at: string;
}

export interface GrantListResponse {
  grants: GrantResponse[];
}

export interface DocumentListParams {
  page?: number;
  page_size?: number;
  q?: string;
  category?: string;
  created_from?: string;
  created_to?: string;
}
