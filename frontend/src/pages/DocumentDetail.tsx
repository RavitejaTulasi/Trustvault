import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  createGrant,
  deleteDocument,
  downloadDocument,
  getDocument,
  getMe,
  listGrants,
  revokeGrant,
  updateDocument,
} from '../auth';
import { ApiError, NetworkError } from '../api';
import type { DocumentResponse, GrantResponse, UserResponse } from '../types';

function describeError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    return err.detail;
  }
  if (err instanceof NetworkError) {
    return err.message;
  }
  return fallback;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KB', 'MB', 'GB'];
  let value = bytes;
  let unitIndex = -1;
  do {
    value /= 1024;
    unitIndex += 1;
  } while (value >= 1024 && unitIndex < units.length - 1);
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

export default function DocumentDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const [user, setUser] = useState<UserResponse | null>(null);
  const [doc, setDoc] = useState<DocumentResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);

  // The list page passes the server-derived effective permission; on a
  // hard refresh it is absent and only the owner-derived view is assumed.
  const effectivePermission =
    (location.state as { effectivePermission?: string } | null)?.effectivePermission ?? null;
  const isOwner = user !== null && doc !== null && user.id === doc.owner_id;
  const canEdit = isOwner || effectivePermission === 'edit';

  const [editing, setEditing] = useState(false);
  const [titleDraft, setTitleDraft] = useState('');
  const [categoryDraft, setCategoryDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  const [deleteArmed, setDeleteArmed] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const [grants, setGrants] = useState<GrantResponse[]>([]);
  const [grantsError, setGrantsError] = useState<string | null>(null);
  const [shareUserId, setShareUserId] = useState('');
  const [sharePermission, setSharePermission] = useState<'read' | 'edit'>('read');
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [revokeArmedId, setRevokeArmedId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const loadGrants = useCallback(
    async (grantsForOwner: boolean) => {
      if (!grantsForOwner) {
        setGrants([]);
        return;
      }
      try {
        const result = await listGrants(id);
        setGrants(result.grants);
      } catch (err) {
        // The server deliberately 404s non-owners; nobody else sees this view.
        setGrantsError(describeError(err, 'Could not load permission grants'));
      }
    },
    [id],
  );

  const loadAll = useCallback(async () => {
    try {
      // The leading await keeps initial state updates out of the effect tick.
      const session = await getMe();
      if (!session) {
        navigate('/login', { replace: true });
        return;
      }
      setUser(session);
      const document = await getDocument(id);
      setDoc(document);
      setTitleDraft(document.title);
      setCategoryDraft(document.category);
      setAccessDenied(false);
      await loadGrants(session.id === document.owner_id);
      setLoading(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Deliberate 404: the document does not exist or the caller has no grant.
        setAccessDenied(true);
        setLoading(false);
        return;
      }
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setLoading(false);
      setLoadError(describeError(err, 'Could not load the document'));
    }
  }, [id, loadGrants, navigate]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- external backend sync; setState runs after awaits
    loadAll();
  }, [loadAll]);

  const handleEdit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEditError(null);
    setSaving(true);
    try {
      const updated = await updateDocument(id, {
        title: titleDraft.trim() || undefined,
        category: categoryDraft.trim() || undefined,
      });
      setDoc(updated);
      setTitleDraft(updated.title);
      setCategoryDraft(updated.category);
      setEditing(false);
    } catch (err) {
      setEditError(describeError(err, 'Update failed. Please try again.'));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteArmed) {
      setDeleteArmed(true);
      return;
    }
    setDeleteArmed(false);
    setDeleting(true);
    setDeleteError(null);
    try {
      await deleteDocument(id);
      navigate('/documents', { replace: true });
    } catch (err) {
      setDeleting(false);
      setDeleteError(describeError(err, 'Delete failed. Please try again.'));
    }
  };

  const handleDownload = async () => {
    setDownloadError(null);
    setDownloading(true);
    try {
      await downloadDocument(id, doc?.original_filename);
    } catch (err) {
      setDownloadError(describeError(err, 'Download failed. Please try again.'));
    } finally {
      setDownloading(false);
    }
  };

  const handleShare = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setShareError(null);
    if (shareUserId.trim() === '') {
      setShareError('A user ID is required.');
      return;
    }
    setSharing(true);
    try {
      await createGrant(id, shareUserId.trim(), sharePermission);
      setShareUserId('');
      await loadGrants(true);
    } catch (err) {
      setShareError(describeError(err, 'Grant failed. Please try again.'));
    } finally {
      setSharing(false);
    }
  };

  const handleRevoke = async (grant: GrantResponse) => {
    if (revokeArmedId !== grant.user_id) {
      setRevokeArmedId(grant.user_id);
      return;
    }
    setRevokeArmedId(null);
    setRevokingId(grant.user_id);
    setShareError(null);
    try {
      await revokeGrant(id, grant.user_id);
      await loadGrants(true);
    } catch (err) {
      setShareError(describeError(err, 'Revoke failed. Please try again.'));
    } finally {
      setRevokingId(null);
    }
  };

  if (loading) {
    return (
      <main className="document-detail" aria-busy="true">
        <p>Loading…</p>
      </main>
    );
  }

  if (accessDenied) {
    return (
      <main className="document-detail">
        <h2>Document not found</h2>
        <p role="alert">
          This document does not exist, or you do not have permission to see it.
        </p>
        <Link to="/documents">Back to documents</Link>
      </main>
    );
  }

  if (loadError || doc === null) {
    return (
      <main className="document-detail">
        <p role="alert" className="error">
          {loadError ?? 'Could not load the document'}
        </p>
        <button type="button" onClick={loadAll}>
          Retry
        </button>
      </main>
    );
  }

  return (
    <main className="document-detail">
      <p>
        <Link to="/documents">← Back to documents</Link>
      </p>
      <h2>{doc.title}</h2>

      <dl className="document-meta">
        <dt>Filename</dt>
        <dd>{doc.original_filename}</dd>
        <dt>Size</dt>
        <dd>{formatSize(doc.file_size_bytes)}</dd>
        <dt>Type</dt>
        <dd>{doc.mime_type}</dd>
        <dt>Category</dt>
        <dd>{doc.category}</dd>
        <dt>Created</dt>
        <dd>{doc.created_at}</dd>
        <dt>Updated</dt>
        <dd>{doc.updated_at}</dd>
      </dl>

      {(downloadError || deleteError) && (
        <p role="alert" className="error">
          {downloadError ?? deleteError}
        </p>
      )}

      <div className="document-actions">
        <button type="button" onClick={handleDownload} disabled={downloading}>
          {downloading ? 'Downloading…' : 'Download'}
        </button>
        {isOwner && (
          <button type="button" onClick={handleDelete} disabled={deleting}>
            {deleteArmed ? 'Confirm delete?' : deleting ? 'Deleting…' : 'Delete'}
          </button>
        )}
      </div>

      {canEdit && (
        <section aria-label="Edit document metadata">
          <h3>Edit metadata</h3>
          {editError && (
            <p role="alert" className="error">
              {editError}
            </p>
          )}
          {!editing ? (
            <button type="button" onClick={() => setEditing(true)}>
              Edit title / category
            </button>
          ) : (
            <form onSubmit={handleEdit}>
              <div>
                <label htmlFor="edit-title">Title</label>
                <input
                  id="edit-title"
                  type="text"
                  value={titleDraft}
                  onChange={(e) => setTitleDraft(e.target.value)}
                  maxLength={255}
                  required
                />
              </div>
              <div>
                <label htmlFor="edit-category">Category</label>
                <input
                  id="edit-category"
                  type="text"
                  value={categoryDraft}
                  onChange={(e) => setCategoryDraft(e.target.value)}
                  maxLength={100}
                  required
                />
              </div>
              <button type="submit" disabled={saving}>
                {saving ? 'Saving…' : 'Save'}
              </button>
              <button type="button" onClick={() => setEditing(false)} disabled={saving}>
                Cancel
              </button>
            </form>
          )}
        </section>
      )}

      {isOwner && (
        <section aria-label="Sharing permissions">
          <h3>Sharing</h3>
          {(grantsError || shareError) && (
            <p role="alert" className="error">
              {grantsError ?? shareError}
            </p>
          )}
          <form onSubmit={handleShare} className="share-form">
            <div>
              <label htmlFor="share-user">User ID</label>
              <input
                id="share-user"
                type="text"
                value={shareUserId}
                onChange={(e) => setShareUserId(e.target.value)}
                maxLength={64}
                placeholder="u_recipient_123"
              />
            </div>
            <div>
              <label htmlFor="share-permission">Permission</label>
              <select
                id="share-permission"
                value={sharePermission}
                onChange={(e) =>
                  setSharePermission(e.target.value === 'edit' ? 'edit' : 'read')
                }
              >
                <option value="read">read</option>
                <option value="edit">edit</option>
              </select>
            </div>
            <button type="submit" disabled={sharing}>
              {sharing ? 'Sharing…' : 'Grant access'}
            </button>
          </form>

          {grants.length === 0 ? (
            <p>No permission grants for this document yet.</p>
          ) : (
            <table className="grants-table">
              <thead>
                <tr>
                  <th scope="col">User ID</th>
                  <th scope="col">Permission</th>
                  <th scope="col">Status</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {grants.map((grant) => (
                  <tr key={grant.id}>
                    <td>{grant.user_id}</td>
                    <td>{grant.permission}</td>
                    <td>{grant.is_revoked ? 'revoked' : 'active'}</td>
                    <td>
                      {!grant.is_revoked && (
                        <button
                          type="button"
                          onClick={() => handleRevoke(grant)}
                          disabled={revokingId === grant.user_id}
                        >
                          {revokeArmedId === grant.user_id
                            ? 'Confirm revoke?'
                            : revokingId === grant.user_id
                              ? 'Revoking…'
                              : 'Revoke'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </main>
  );
}
