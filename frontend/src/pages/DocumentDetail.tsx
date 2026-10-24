import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import {
  createGrant,
  deleteDocument,
  downloadDocument,
  getDocument,
  listGrants,
  revokeGrant,
  resolveGrantRecipient,
  updateDocument,
} from '../auth';
import { ApiError, listDocumentActivity } from '../api';
import type { AuditEventResponse, DocumentResponse, GrantResponse } from '../types';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import Tabs from '../components/Tabs';
import { OutcomeBadge, PermissionBadge, StatusBadge } from '../components/Badges';
import Skeleton from '../components/Skeleton';
import { useToast } from '../components/useToast';
import {
  ChevronLeftIcon,
  DownloadIcon,
  FileIcon,
  KeyIcon,
  RefreshIcon,
  ShareIcon,
  ShieldIcon,
  TrashIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import {
  describeError,
  formatBytes,
  formatDateTime,
  shortId,
} from '../lib/format';

const ACTIVITY_PAGE_SIZE = 10;

export default function DocumentDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const { pushToast } = useToast();

  const [doc, setDoc] = useState<DocumentResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [accessDenied, setAccessDenied] = useState(false);

  const effectivePermission =
    (location.state as { effectivePermission?: string } | null)?.effectivePermission ?? null;
  const isOwner = user !== null && doc !== null && user.id === doc.owner_id;
  const canEdit = isOwner || effectivePermission === 'edit';
  const isAdmin = user?.role === 'admin';

  const [tab, setTab] = useState('overview');

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
  const [shareEmail, setShareEmail] = useState('');
  const [resolvedShareUserId, setResolvedShareUserId] = useState<string | null>(null);
  const [sharePermission, setSharePermission] = useState<'read' | 'edit'>('read');
  const [reviewingShare, setReviewingShare] = useState(false);
  const [resolvingShare, setResolvingShare] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [revokeArmedId, setRevokeArmedId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const [activityEvents, setActivityEvents] = useState<AuditEventResponse[]>([]);
  const [activityTotal, setActivityTotal] = useState(0);
  const [activityPage, setActivityPage] = useState(1);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityError, setActivityError] = useState<string | null>(null);
  const activityRequestRef = useRef(0);

  const loadGrants = useCallback(
    async (grantsForOwner: boolean) => {
      if (!grantsForOwner) {
        setGrants([]);
        setGrantsError(null);
        return;
      }
      try {
        const result = await listGrants(id);
        setGrants(result.grants);
      } catch (err) {
        setGrantsError(describeError(err, 'Could not load permission grants'));
      }
    },
    [id],
  );

  const loadAll = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    setAccessDenied(false);
    try {
      const document = await getDocument(id);
      setDoc(document);
      setTitleDraft(document.title);
      setCategoryDraft(document.category);
      if (user) {
        await loadGrants(user.id === document.owner_id);
      }
      setLoading(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
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
  }, [id, loadGrants, navigate, user]);

  useEffect(() => {
    if (!user) {
      return;
    }
    // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
    void loadAll();
  }, [loadAll, user]);

  const loadActivity = useCallback(
    async (targetPage: number) => {
      const request = activityRequestRef.current + 1;
      activityRequestRef.current = request;
      setActivityLoading(true);
      setActivityError(null);
      try {
        const result = await listDocumentActivity({
          document_id: id,
          page: targetPage,
          page_size: ACTIVITY_PAGE_SIZE,
        });
        if (request !== activityRequestRef.current) {
          return;
        }
        setActivityEvents(result.events);
        setActivityTotal(result.total);
        setActivityPage(result.page);
        setActivityLoading(false);
      } catch (err) {
        if (request !== activityRequestRef.current) {
          return;
        }
        setActivityLoading(false);
        setActivityError(describeError(err, 'Could not load document activity'));
      }
    },
    [id],
  );

  useEffect(() => {
    if (!isAdmin || tab !== 'activity') {
      return;
    }
    // eslint-disable-next-line react/set-state-in-effect -- lazy tab fetch reflects server state
    void loadActivity(1);
  }, [isAdmin, loadActivity, tab]);

  const handleTabChange = (next: string) => {
    if (next === 'overview' || next === 'access' || (next === 'activity' && isAdmin)) {
      setTab(next);
    }
  };

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
      pushToast({ title: 'Document updated', tone: 'success' });
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
      pushToast({ title: 'Document deleted', tone: 'success' });
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

  const handleShareReview = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setShareError(null);
    setResolvedShareUserId(null);
    const email = shareEmail.trim();
    if (email === '') {
      setShareError('Enter the email address for an existing active TrustVault account.');
      return;
    }
    setResolvingShare(true);
    try {
      const recipient = await resolveGrantRecipient(id, email);
      setResolvedShareUserId(recipient.user_id);
      setReviewingShare(true);
    } catch (err) {
      setShareError(describeError(err, 'Could not find an active recipient account.'));
    } finally {
      setResolvingShare(false);
    }
  };

  const handleConfirmShare = async () => {
    setShareError(null);
    if (resolvedShareUserId === null) {
      setShareError('Resolve an existing active recipient before granting access.');
      setReviewingShare(false);
      return;
    }
    setSharing(true);
    try {
      await createGrant(id, resolvedShareUserId, sharePermission);
      setShareEmail('');
      setResolvedShareUserId(null);
      setReviewingShare(false);
      await loadGrants(true);
      pushToast({ title: 'Access granted', tone: 'success' });
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
      pushToast({ title: 'Access revoked', tone: 'success' });
    } catch (err) {
      setShareError(describeError(err, 'Revoke failed. Please try again.'));
    } finally {
      setRevokingId(null);
    }
  };

  if (!user) {
    return (
      <main className="standalone-state" aria-busy={sessionLoading || undefined}>
        {sessionError ? (
          <>
            <div role="alert" className="alert alert-error">
              {sessionError}
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void reload()}>
              <RefreshIcon width={16} height={16} />
              Retry
            </button>
          </>
        ) : (
          <>
            <span className="brand-mark">
              <ShieldIcon width={22} height={22} />
            </span>
            <p className="section-copy">Loading document access…</p>
          </>
        )}
      </main>
    );
  }

  if (loading) {
    return (
      <AppShell user={user}>
        <div className="panel" aria-busy="true">
          <div className="panel-body">
            <Skeleton lines={7} label="Loading document" />
          </div>
        </div>
      </AppShell>
    );
  }

  if (accessDenied) {
    return (
      <AppShell user={user}>
        <div className="standalone-state">
          <span className="empty-state-icon" aria-hidden="true">
            <FileIcon width={24} height={24} />
          </span>
          <h1 className="page-title">Document not found</h1>
          <p role="alert" className="page-description">
            This document does not exist, or you do not have permission to see it.
          </p>
          <Link to="/documents" className="btn btn-secondary">
            Back to documents
          </Link>
        </div>
      </AppShell>
    );
  }

  if (loadError || doc === null) {
    return (
      <AppShell user={user}>
        <div className="standalone-state">
          <div role="alert" className="alert alert-error">
            {loadError ?? 'Could not load the document'}
          </div>
          <button type="button" className="btn btn-primary" onClick={() => void loadAll()}>
            <RefreshIcon width={16} height={16} />
            Retry
          </button>
        </div>
      </AppShell>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'access', label: 'Access' },
    ...(isAdmin ? [{ id: 'activity', label: 'Activity' }] : []),
  ];
  const activityTotalPages = Math.max(1, Math.ceil(activityTotal / ACTIVITY_PAGE_SIZE));
  const hasActivityPrev = activityPage > 1 && !activityLoading;
  const hasActivityNext = activityPage < activityTotalPages && !activityLoading;

  return (
    <AppShell user={user}>
      <div className="document-detail">
        <Link to="/documents" className="back-link">
          <ChevronLeftIcon width={14} height={14} />
          Back to documents
        </Link>

        <PageHeader
          eyebrow={isOwner ? 'Owned document' : `${effectivePermission ?? 'Shared'} access`}
          title={doc.title}
          backTo="/documents"
          backLabel="My documents"
          description={`Document ${shortId(doc.id)} · access is re-checked on every request.`}
          actions={
            <>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => void handleDownload()}
                disabled={downloading}
              >
                <DownloadIcon width={15} height={15} />
                {downloading ? 'Downloading…' : 'Download'}
              </button>
              {isOwner && (
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => void handleDelete()}
                  disabled={deleting}
                >
                  <TrashIcon width={15} height={15} />
                  {deleteArmed ? 'Confirm delete?' : deleting ? 'Deleting…' : 'Delete'}
                </button>
              )}
            </>
          }
        />

        {(downloadError || deleteError) && (
          <div role="alert" className="alert alert-error">
            {downloadError ?? deleteError}
          </div>
        )}

        <Tabs label="Document sections" tabs={tabs} value={tab} onChange={handleTabChange} />

        {tab === 'overview' && (
          <div role="tabpanel" aria-label="Overview" className="tab-panel">
            <div className="detail-grid">
              <section className="panel" aria-labelledby="document-meta-title">
                <div className="panel-header">
                  <div>
                    <h2 id="document-meta-title" className="panel-title">
                      Metadata
                    </h2>
                    <p className="panel-description">Values stored for this document.</p>
                  </div>
                  <PermissionBadge
                    permission={isOwner ? 'owner' : effectivePermission === 'edit' ? 'edit' : 'read'}
                  />
                </div>
                <div className="panel-body">
                  <dl className="document-meta">
                    <dt>Category</dt>
                    <dd>{doc.category || 'Uncategorized'}</dd>
                    <dt>Owner</dt>
                    <dd className="mono">{shortId(doc.owner_id)}</dd>
                    <dt>Created</dt>
                    <dd>{formatDateTime(doc.created_at)}</dd>
                    <dt>Updated</dt>
                    <dd>{formatDateTime(doc.updated_at)}</dd>
                  </dl>
                </div>
              </section>

              <div className="detail-side">
                <section className="panel" aria-labelledby="file-title">
                  <div className="panel-header">
                    <div>
                      <h2 id="file-title" className="panel-title">
                        File
                      </h2>
                      <p className="panel-description">Original upload details.</p>
                    </div>
                    <FileIcon width={17} height={17} />
                  </div>
                  <div className="panel-body">
                    <div className="snapshot-list">
                      <div className="snapshot-row">
                        <span className="snapshot-label">Filename</span>
                        <span className="snapshot-value">{doc.original_filename}</span>
                      </div>
                      <div className="snapshot-row">
                        <span className="snapshot-label">Size</span>
                        <span className="snapshot-value">{formatBytes(doc.file_size_bytes)}</span>
                      </div>
                      <div className="snapshot-row">
                        <span className="snapshot-label">Type</span>
                        <span className="snapshot-value">{doc.mime_type}</span>
                      </div>
                    </div>
                  </div>
                </section>

                {canEdit && (
                  <section className="panel" aria-labelledby="edit-document-title">
                    <div className="panel-header">
                      <div>
                        <h2 id="edit-document-title" className="panel-title">
                          Edit metadata
                        </h2>
                        <p className="panel-description">
                          Server-confirmed changes to title and category.
                        </p>
                      </div>
                    </div>
                    <div className="panel-body">
                      {editError && (
                        <div role="alert" className="alert alert-error">
                          {editError}
                        </div>
                      )}
                      {!editing ? (
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => setEditing(true)}
                        >
                          Edit title / category
                        </button>
                      ) : (
                        <form onSubmit={handleEdit} className="auth-form">
                          <div className="field">
                            <label htmlFor="edit-title">Title</label>
                            <input
                              id="edit-title"
                              className="input"
                              type="text"
                              value={titleDraft}
                              onChange={(e) => setTitleDraft(e.target.value)}
                              maxLength={255}
                              required
                            />
                          </div>
                          <div className="field">
                            <label htmlFor="edit-category">Category</label>
                            <input
                              id="edit-category"
                              className="input"
                              type="text"
                              value={categoryDraft}
                              onChange={(e) => setCategoryDraft(e.target.value)}
                              maxLength={100}
                              required
                            />
                          </div>
                          <div className="form-actions">
                            <button type="submit" className="btn btn-primary" disabled={saving}>
                              {saving ? 'Saving…' : 'Save'}
                            </button>
                            <button
                              type="button"
                              className="btn btn-ghost"
                              onClick={() => setEditing(false)}
                              disabled={saving}
                            >
                              Cancel
                            </button>
                          </div>
                        </form>
                      )}
                    </div>
                  </section>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === 'access' && (
          <div role="tabpanel" aria-label="Access" className="tab-panel">
            {isOwner ? (
              <section className="panel panel-sharing" aria-labelledby="sharing-permissions-title">
                <div className="panel-header">
                  <div>
                    <h2 id="sharing-permissions-title" className="panel-title">
                      Sharing
                    </h2>
                    <p className="panel-description">
                      Share with an existing, active TrustVault account by email.
                    </p>
                  </div>
                  <StatusPill />
                </div>
                <div className="panel-body">
                  {(grantsError || shareError) && (
                    <div role="alert" className="alert alert-error">
                      {grantsError ?? shareError}
                    </div>
                  )}
                  {!reviewingShare ? (
                    <form onSubmit={handleShareReview} className="share-form">
                      <div className="field">
                        <label htmlFor="share-email">Recipient email</label>
                        <input
                          id="share-email"
                          className="input"
                          type="email"
                          value={shareEmail}
                          onChange={(e) => setShareEmail(e.target.value)}
                          maxLength={254}
                          autoComplete="off"
                          required
                          placeholder="recipient@example.com"
                        />
                      </div>
                      <div className="field">
                        <label htmlFor="share-permission">Permission</label>
                        <select
                          id="share-permission"
                          className="select"
                          value={sharePermission}
                          onChange={(e) =>
                            setSharePermission(e.target.value === 'edit' ? 'edit' : 'read')
                          }
                        >
                          <option value="read">read</option>
                          <option value="edit">edit</option>
                        </select>
                      </div>
                      <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={resolvingShare || sharing}
                      >
                        <ShareIcon width={15} height={15} />
                        {resolvingShare ? 'Finding account…' : 'Review grant'}
                      </button>
                    </form>
                  ) : (
                    <div className="share-review" role="group" aria-label="Review grant">
                      <dl className="document-meta">
                        <dt>Recipient</dt>
                        <dd className="mono">{shareEmail.trim()}</dd>
                        <dt>Permission</dt>
                        <dd>
                          <PermissionBadge permission={sharePermission} />
                        </dd>
                      </dl>
                      <div className="form-actions">
                        <button
                          type="button"
                          className="btn btn-primary"
                          onClick={() => void handleConfirmShare()}
                          disabled={sharing}
                        >
                          <ShareIcon width={15} height={15} />
                          {sharing ? 'Sharing…' : 'Confirm grant access'}
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => {
                            setReviewingShare(false);
                            setResolvedShareUserId(null);
                          }}
                          disabled={sharing}
                        >
                          Back
                        </button>
                      </div>
                    </div>
                  )}

                  {grants.length === 0 ? (
                    <div className="empty-state">
                      <span className="empty-state-icon" aria-hidden="true">
                        <KeyIcon width={24} height={24} />
                      </span>
                      <p className="empty-state-title">
                        No permission grants for this document yet.
                      </p>
                      <p className="empty-state-copy">
                        Add a recipient above to grant read or edit access.
                      </p>
                    </div>
                  ) : (
                    <div className="table-wrap grants-table">
                      <table>
                        <caption>Permission grants</caption>
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
                              <td className="mono">{grant.user_id}</td>
                              <td>
                                <PermissionBadge permission={grant.permission} />
                              </td>
                              <td>{grant.is_revoked ? 'revoked' : 'active'}</td>
                              <td>
                                {!grant.is_revoked && (
                                  <button
                                    type="button"
                                    className="btn btn-danger btn-sm"
                                    onClick={() => void handleRevoke(grant)}
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
                    </div>
                  )}
                </div>
              </section>
            ) : (
              <section className="panel" aria-labelledby="access-title">
                <div className="panel-header">
                  <div>
                    <h2 id="access-title" className="panel-title">
                      Your access
                    </h2>
                    <p className="panel-description">Sharing is managed by the document owner.</p>
                  </div>
                  {effectivePermission === 'read' || effectivePermission === 'edit' ? (
                    <PermissionBadge permission={effectivePermission} />
                  ) : (
                    <StatusBadge label="Re-checked per request" />
                  )}
                </div>
                <div className="panel-body">
                  <p className="section-copy">
                    TrustVault confirms your permission on every request. Permission grants for
                    this document are only visible to its owner.
                  </p>
                </div>
              </section>
            )}
          </div>
        )}

        {isAdmin && tab === 'activity' && (
          <div role="tabpanel" aria-label="Activity" className="tab-panel">
            <section className="panel" aria-labelledby="document-activity-title">
              <div className="panel-header">
                <div>
                  <h2 id="document-activity-title" className="panel-title">
                    Document activity
                  </h2>
                  <p className="panel-description">
                    Audit events tied to this document, newest first.
                  </p>
                </div>
              </div>
              <div className="panel-body">
                {activityError && (
                  <div role="alert" className="alert alert-error">
                    {activityError}
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => void loadActivity(1)}
                    >
                      Retry
                    </button>
                  </div>
                )}
                {activityLoading ? (
                  <Skeleton lines={5} label="Loading document activity" />
                ) : activityEvents.length === 0 ? (
                  <div className="empty-state">
                    <p className="empty-state-title">No activity recorded for this document yet.</p>
                  </div>
                ) : (
                  <>
                    <div className="table-wrap">
                      <table>
                        <caption>{activityTotal} events</caption>
                        <thead>
                          <tr>
                            <th scope="col">Time</th>
                            <th scope="col">Action</th>
                            <th scope="col">Actor</th>
                            <th scope="col">Outcome</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activityEvents.map((event) => (
                            <tr key={event.id}>
                              <td>{formatDateTime(event.timestamp)}</td>
                              <td>
                                <span className="cell-title-link">{event.action}</span>
                              </td>
                              <td className="mono">{shortId(event.actor_id)}</td>
                              <td>
                                <OutcomeBadge outcome={event.outcome} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <nav className="pagination" aria-label="Document activity pagination">
                      <span className="pagination-info">
                        Page {activityPage} of {activityTotalPages}
                      </span>
                      <div className="pagination-controls">
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          disabled={!hasActivityPrev}
                          onClick={() => void loadActivity(activityPage - 1)}
                        >
                          Previous
                        </button>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          disabled={!hasActivityNext}
                          onClick={() => void loadActivity(activityPage + 1)}
                        >
                          Next
                        </button>
                      </div>
                    </nav>
                  </>
                )}
              </div>
            </section>
          </div>
        )}
      </div>
    </AppShell>
  );
}

function StatusPill() {
  return (
    <span className="badge badge-owner">
      <ShieldIcon width={12} height={12} />
      Owner controls
    </span>
  );
}
