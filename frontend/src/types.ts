export interface UserResponse {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  must_change_password: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserUpdateRequest {
  full_name?: string;
  password?: string;
}

export interface AdminUserCreateRequest {
  email: string;
  password: string;
  full_name: string;
  role: Role;
  is_active: boolean;
}

export interface AdminUserUpdateRequest {
  role?: Role;
  is_active?: boolean;
}

export interface UserListResponse {
  users: UserResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface UserSessionsRevokedResponse {
  user_id: string;
  sessions_revoked: number;
}

export interface AdminPasswordResetResponse {
  user_id: string;
  sessions_revoked: number;
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

export interface GrantRecipientLookupResponse {
  user_id: string;
}

export interface GrantListResponse {
  grants: GrantResponse[];
}

export interface DocumentListParams {
  page?: number;
  page_size?: number;
  q?: string;
  category?: string;
  owner_id?: string;
  created_from?: string;
  created_to?: string;
}

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditAnchorHealth {
  status: string;
  mode: string;
  independent: boolean;
  external_adapter: boolean;
  independence_verified: boolean;
  available: boolean;
  last_checkpoint_at: string | null;
  checkpoint_sequence: number | null;
  checkpoint_age_seconds: number | null;
  max_age_seconds: number;
  overdue: boolean;
  failure_reason: string | null;
  scheduler?: Record<string, unknown>;
}

export interface HealthResponse {
  status: string;
  app: string;
  environment: string;
  version: string;
  timestamp: string;
  database: string;
  storage: string;
  components: {
    database?: Record<string, unknown>;
    storage?: Record<string, unknown>;
    audit_anchor?: AuditAnchorHealth;
    [key: string]: unknown;
  };
}

export interface AuditEventResponse {
  id: string;
  sequence_number: number;
  timestamp: string;
  actor_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: AuditOutcome;
  request_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  details: Record<string, unknown> | null;
}

export interface AuditEventListParams {
  page?: number;
  page_size?: number;
  actor_id?: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: AuditOutcome;
  timestamp_from?: string;
  timestamp_to?: string;
}

export interface AuditEventListResponse {
  events: AuditEventResponse[];
  total: number;
  page: number;
  page_size: number;
}

export type AuditVerificationStatus = 'VALID' | 'INVALID' | 'INCOMPLETE';

export interface AuditVerificationResponse {
  status: AuditVerificationStatus;
  is_valid: boolean;
  records_verified: number;
  failure_reason: string | null;
}

export type AuditCheckpointCreateStatus = 'CREATED' | 'ALREADY_PRESENT';

export interface AuditCheckpointCreateResponse {
  status: AuditCheckpointCreateStatus;
  anchor_mode: string;
  stream_id: string;
  sequence_number: number;
  created_at: string;
}

export interface AuditCheckpointInfoResponse {
  anchor_mode: string;
  available: boolean;
  stream_id: string | null;
  sequence_number: number | null;
  created_at: string | null;
  format_version: number | null;
}

export type AuditCheckpointVerificationStatus =
  | 'VALID'
  | 'INVALID'
  | 'INCOMPLETE'
  | 'UNAVAILABLE';

export interface AuditCheckpointVerificationResponse {
  status: AuditCheckpointVerificationStatus;
  is_valid: boolean;
  records_verified: number;
  checkpoint_sequence: number | null;
  chain_head_sequence: number | null;
  failure_reason: string | null;
  anchor_mode: string;
}
