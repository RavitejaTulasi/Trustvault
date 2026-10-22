import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import EmptyState from '../components/EmptyState';
import Tabs from '../components/Tabs';
import { PermissionBadge } from '../components/Badges';
import {
  ChevronDownIcon,
  FileIcon,
  KeyIcon,
  RefreshIcon,
  SearchIcon,
  ShareIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import { listGrants, revokeGrant } from '../auth';
import { fetchAllVisibleDocuments } from '../lib/documents';
import { ApiError } from '../api';
import {
  describeError,
  formatDateTime,
  permissionLabel,
  shortId,
} from '../lib/format';
import type { DocumentListItem, GrantResponse } from '../types';

export default function AccessSharing() {
  const navigate = useNavigate();
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const [documents, setDocuments] = useState<DocumentListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState<'manage' | 'mine'>('manage');

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [grants, setGrants] = useState<GrantResponse[]>([]);
  const [grantsLoading, setGrantsLoading] = useState(false);
  const [grantsError, setGrantsError] = useState<string | null>(null);
  const [revokeArmedId, setRevokeArmedId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const grantsRequestRef = useRef(0);

  const loadDocuments = useCallback(async () => {
    if (!user) {
      return;
    }
    setLoading(true);
    setLoadError(null);
    try {
      const visible = await fetchAllVisibleDocuments();
      setDocuments(visible);
      setLoading(false);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setLoading(false);
      setLoadError(describeError(err, 'Could not load access grants'));
    }
  }, [navigate, user]);

  useEffect(() => {
    if (user) {
      // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
      void loadDocuments();
    }
  }, [loadDocuments, user]);

  const ownedDocs = useMemo(
    () => documents.filter((doc) => doc.effective_permission === 'owner'),
    [documents],
  );
  const sharedDocs = useMemo(
    () => documents.filter((doc) => doc.effective_permission !== 'owner'),
    [documents],
  );

  const filtered = useMemo(() => {
    const source = tab === 'manage' ? ownedDocs : sharedDocs;
    const query = search.trim().toLowerCase();
    if (query === '') {
      return source;
    }
    return source.filter(
      (doc) =>
        doc.title.toLowerCase().includes(query) ||
        doc.category.toLowerCase().includes(query),
    );
  }, [ownedDocs, search, sharedDocs, tab]);

  const handleTabChange = (next: string) => {
    if (next !== 'manage' && next !== 'mine') {
      return;
    }
    setTab(next);
    setExpandedId(null);
    setGrants([]);
    setNotice(null);
  };

  const loadGrantsFor = useCallback(
    async (documentId: string) => {
      const request = grantsRequestRef.current + 1;
      grantsRequestRef.current = request;
      setGrantsLoading(true);
      setGrantsError(null);
      try {
        const result = await listGrants(documentId);
        if (request !== grantsRequestRef.current) {
          return;
        }
        setGrants(result.grants);
      } catch (err) {
        if (request !== grantsRequestRef.current) {
          return;
        }
        setGrantsError(describeError(err, 'Could not load grants for this document'));
      } finally {
        if (request === grantsRequestRef.current) {
          setGrantsLoading(false);
        }
      }
    },
    [],
  );

  const toggleAccess = async (doc: DocumentListItem) => {
    setNotice(null);
    setRevokeArmedId(null);
    if (expandedId === doc.id) {
      setExpandedId(null);
      setGrants([]);
      return;
    }
    setExpandedId(doc.id);
    setGrants([]);
    await loadGrantsFor(doc.id);
  };

  const handleRevoke = async (documentId: string, grant: GrantResponse) => {
    const key = `${documentId}:${grant.user_id}`;
    if (revokeArmedId !== key) {
      setRevokeArmedId(key);
      return;
    }
    setRevokeArmedId(null);
    setRevokingId(key);
    setGrantsError(null);
    setNotice(null);
    try {
      await revokeGrant(documentId, grant.user_id);
      setNotice(`Access revoked for ${shortId(grant.user_id)}.`);
      // Re-read from the server so the UI reflects the committed state.
      await loadGrantsFor(documentId);
    } catch (err) {
      setGrantsError(describeError(err, 'Revoke failed. Please try again.'));
    } finally {
      setRevokingId(null);
    }
  };

  if (sessionLoading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <KeyIcon width={24} height={24} />
        </span>
        <p>Loading access controls…</p>
      </div>
    );
  }

  if (sessionError || !user) {
    return (
      <main className="page-content">
        <div className="panel">
          <div className="panel-body">
            <div role="alert" className="alert alert-error">
              {sessionError ?? 'Could not load your session'}
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void reload()}>
              <RefreshIcon width={17} height={17} />
              Retry
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <AppShell user={user}>
      <PageHeader
        eyebrow="Sharing"
        title="Access & Sharing"
        description="Review the grants on documents you own, and the documents shared with you. Revocations are confirmed by the server before the UI updates."
        backTo="/"
        backLabel="Overview"
      />

      {loadError && (
        <div role="alert" className="alert alert-error">
          {loadError}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void loadDocuments()}
          >
            Retry
          </button>
        </div>
      )}

      {notice && (
        <div role="status" className="notice notice-success">
          {notice}
        </div>
      )}

      <Tabs
        label="Access sections"
        tabs={[
          { id: 'manage', label: 'Manage sharing' },
          { id: 'mine', label: 'My access' },
        ]}
        value={tab}
        onChange={handleTabChange}
      />

      <div
        role="tabpanel"
        aria-label={tab === 'manage' ? 'Manage sharing' : 'My access'}
        className="tab-panel"
      >
        <div className="toolbar">
          <div className="field">
            <label htmlFor="access-search">
              <SearchIcon width={13} height={13} /> Search documents
            </label>
            <input
              id="access-search"
              className="input"
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Title or category"
            />
          </div>
        </div>

        {loading ? (
          <div className="panel" aria-busy="true">
            <div className="skeleton-table">
              {[0, 1, 2, 3].map((row) => (
                <div key={row} className="skeleton skeleton-line" />
              ))}
            </div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="panel">
            <EmptyState
              title={
                tab === 'manage'
                  ? ownedDocs.length === 0
                    ? 'No documents to manage'
                    : 'No matching documents'
                  : sharedDocs.length === 0
                    ? 'No shared documents'
                    : 'No matching documents'
              }
              description={
                tab === 'manage'
                  ? ownedDocs.length === 0
                    ? 'You can manage sharing only on documents you own. Upload a document to get started.'
                    : 'Try a different title or category.'
                  : sharedDocs.length === 0
                    ? 'Documents other people share with you will appear here.'
                    : 'Try a different title or category.'
              }
              action={
                tab === 'manage' && ownedDocs.length === 0 ? (
                  <Link to="/documents?upload=1" className="btn btn-primary btn-sm">
                    Upload a document
                  </Link>
                ) : undefined
              }
            />
          </div>
        ) : tab === 'manage' ? (
          <>
            <div className="summary-strip">
              <span>
                <strong>{ownedDocs.length}</strong> document
                {ownedDocs.length === 1 ? '' : 's'} owned
              </span>
              <span>Select a document to inspect its grants.</span>
            </div>
            <div className="table-wrap">
              <table>
                <caption>Sharing controls</caption>
                <thead>
                  <tr>
                    <th scope="col">Document</th>
                    <th scope="col" className="hide-sm">
                      Category
                    </th>
                    <th scope="col" className="hide-sm">
                      Last updated
                    </th>
                    <th scope="col">Access</th>
                    <th scope="col">Grants</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((doc) => {
                    const expanded = expandedId === doc.id;
                    return (
                      <DocumentRowGroup
                        key={doc.id}
                        doc={doc}
                        expanded={expanded}
                        grants={expanded ? grants : []}
                        grantsLoading={expanded && grantsLoading}
                        grantsError={expanded ? grantsError : null}
                        revokeArmedId={revokeArmedId}
                        revokingId={revokingId}
                        onToggle={() => void toggleAccess(doc)}
                        onRevoke={(grant) => void handleRevoke(doc.id, grant)}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <>
            <div className="summary-strip">
              <span>
                <strong>{sharedDocs.length}</strong> document
                {sharedDocs.length === 1 ? '' : 's'} shared with you
              </span>
              <span>Open a document to see its details.</span>
            </div>
            <div className="table-wrap">
              <table>
                <caption>Documents shared with you</caption>
                <thead>
                  <tr>
                    <th scope="col">Document</th>
                    <th scope="col" className="hide-sm">
                      Category
                    </th>
                    <th scope="col" className="hide-sm">
                      Shared by
                    </th>
                    <th scope="col">Access</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((doc) => (
                    <tr key={doc.id}>
                      <td>
                        <div className="cell-title">
                          <Link
                            to={`/documents/${doc.id}`}
                            state={{ effectivePermission: doc.effective_permission }}
                            className="cell-title-link"
                          >
                            {doc.title}
                          </Link>
                          <span className="cell-sub">{doc.original_filename}</span>
                        </div>
                      </td>
                      <td className="hide-sm">{doc.category}</td>
                      <td className="hide-sm mono">{shortId(doc.owner_id)}</td>
                      <td>
                        <PermissionBadge permission={doc.effective_permission} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}

interface DocumentRowGroupProps {
  doc: DocumentListItem;
  expanded: boolean;
  grants: GrantResponse[];
  grantsLoading: boolean;
  grantsError: string | null;
  revokeArmedId: string | null;
  revokingId: string | null;
  onToggle: () => void;
  onRevoke: (grant: GrantResponse) => void;
}

function DocumentRowGroup({
  doc,
  expanded,
  grants,
  grantsLoading,
  grantsError,
  revokeArmedId,
  revokingId,
  onToggle,
  onRevoke,
}: DocumentRowGroupProps) {
  return (
    <>
      <tr>
        <td>
          <div className="cell-title">
            <Link
              to={`/documents/${doc.id}`}
              state={{ effectivePermission: doc.effective_permission }}
              className="cell-title-link"
            >
              {doc.title}
            </Link>
            <span className="cell-sub">{doc.original_filename}</span>
          </div>
        </td>
        <td className="hide-sm">{doc.category}</td>
        <td className="hide-sm">{formatDateTime(doc.updated_at)}</td>
        <td>
          <PermissionBadge permission={doc.effective_permission} />
        </td>
        <td>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            aria-expanded={expanded}
            onClick={onToggle}
          >
            <ShareIcon width={14} height={14} />
            {expanded ? 'Hide access' : 'View access'}
            <ChevronDownIcon
              width={13}
              height={13}
              style={{ transform: expanded ? 'rotate(180deg)' : undefined }}
            />
          </button>
        </td>
      </tr>
      {expanded && (
        <tr className="access-expanded">
          <td colSpan={5}>
            <div className="access-panel">
              <div className="access-panel-header">
                <p className="access-panel-title">Grants for “{doc.title}”</p>
                <Link
                  to={`/documents/${doc.id}`}
                  state={{ effectivePermission: doc.effective_permission }}
                  className="btn btn-ghost btn-sm"
                >
                  <FileIcon width={14} height={14} />
                  Open document
                </Link>
              </div>

              {grantsError && (
                <div role="alert" className="alert alert-error">
                  {grantsError}
                </div>
              )}

              {grantsLoading ? (
                <div aria-busy="true">
                  <div className="skeleton skeleton-line" />
                  <div className="skeleton skeleton-line" />
                </div>
              ) : grants.length === 0 ? (
                <div className="access-empty">
                  No permission grants for this document yet.
                </div>
              ) : (
                <div className="grant-list">
                  {grants.map((grant) => {
                    const key = `${doc.id}:${grant.user_id}`;
                    return (
                      <div key={grant.id} className="grant-row">
                        <span className="recent-icon">
                          <KeyIcon width={16} height={16} />
                        </span>
                        <div className="grant-copy">
                          <p className="grant-user">{grant.user_id}</p>
                          <p className="grant-meta">
                            {grant.is_revoked
                              ? 'Revoked grant'
                              : `${permissionLabel(grant.permission)} · granted ${formatDateTime(grant.created_at)}`}
                          </p>
                        </div>
                        <div className="grant-actions">
                          <span
                            className={`badge ${grant.is_revoked ? 'badge-read' : `badge-${grant.permission}`}`}
                          >
                            {grant.is_revoked ? 'revoked' : grant.permission}
                          </span>
                          {!grant.is_revoked && (
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => onRevoke(grant)}
                              disabled={revokingId === key}
                            >
                              {revokeArmedId === key
                                ? 'Confirm revoke?'
                                : revokingId === key
                                  ? 'Revoking…'
                                  : 'Revoke'}
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
