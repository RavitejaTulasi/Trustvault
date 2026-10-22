import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import EmptyState from '../components/EmptyState';
import { PermissionBadge } from '../components/Badges';
import {
  DownloadIcon,
  FileIcon,
  RefreshIcon,
  SearchIcon,
  ShareIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import { downloadDocument } from '../auth';
import { fetchAllVisibleDocuments } from '../lib/documents';
import { ApiError } from '../api';
import { describeError, formatBytes, formatDate, shortId } from '../lib/format';
import type { DocumentListItem } from '../types';

export default function SharedWithMe() {
  const navigate = useNavigate();
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const [documents, setDocuments] = useState<DocumentListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadShared = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const visible = await fetchAllVisibleDocuments();
      setDocuments(visible.filter((doc) => doc.effective_permission !== 'owner'));
      setLoading(false);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setLoading(false);
      setLoadError(describeError(err, 'Could not load shared documents'));
    }
  }, [navigate]);

  useEffect(() => {
    if (user) {
      // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
      void loadShared();
    }
  }, [loadShared, user]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (query === '') {
      return documents;
    }
    return documents.filter(
      (doc) =>
        doc.title.toLowerCase().includes(query) ||
        doc.original_filename.toLowerCase().includes(query) ||
        doc.category.toLowerCase().includes(query),
    );
  }, [documents, search]);

  const handleDownload = async (doc: DocumentListItem) => {
    setActionError(null);
    setDownloadingId(doc.id);
    try {
      await downloadDocument(doc.id, doc.original_filename);
    } catch (err) {
      setActionError(describeError(err, `Could not download "${doc.title}"`));
    } finally {
      setDownloadingId(null);
    }
  };

  if (sessionLoading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <ShareIcon width={24} height={24} />
        </span>
        <p>Loading shared documents…</p>
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
        eyebrow="Shared"
        title="Shared With Me"
        description="Documents another owner has explicitly granted you access to. You never see anything else."
        backTo="/"
        backLabel="Overview"
      />

      {loadError && (
        <div role="alert" className="alert alert-error">
          {loadError}
          <button type="button" className="btn btn-secondary btn-sm" onClick={() => void loadShared()}>
            Retry
          </button>
        </div>
      )}

      {actionError && (
        <div role="alert" className="alert alert-error">
          {actionError}
        </div>
      )}

      <div className="toolbar">
        <div className="field">
          <label htmlFor="shared-search">
            <SearchIcon width={13} height={13} /> Search shared documents
          </label>
          <input
            id="shared-search"
            className="input"
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Title, filename, or category"
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
            title={documents.length === 0 ? 'Nothing shared yet' : 'No matching documents'}
            description={
              documents.length === 0
                ? 'When an owner grants you read or edit access, the document will appear here.'
                : 'Try a different title, filename, or category.'
            }
            action={
              documents.length === 0 ? (
                <Link to="/documents" className="btn btn-secondary btn-sm">
                  View all documents
                </Link>
              ) : undefined
            }
          />
        </div>
      ) : (
        <>
          <div className="summary-strip">
            <span>
              <strong>{filtered.length}</strong> shared document
              {filtered.length === 1 ? '' : 's'} visible
            </span>
            <span>Access is re-checked on every request.</span>
          </div>
          <div className="table-wrap">
            <table>
              <caption>Shared with {user.email}</caption>
              <thead>
                <tr>
                  <th scope="col">Document</th>
                  <th scope="col" className="hide-sm">
                    Owner
                  </th>
                  <th scope="col" className="hide-sm">
                    Size
                  </th>
                  <th scope="col">Access</th>
                  <th scope="col" className="hide-sm">
                    Updated
                  </th>
                  <th scope="col">Actions</th>
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
                        <span className="cell-sub">
                          {doc.original_filename} · {doc.category}
                        </span>
                      </div>
                    </td>
                    <td className="hide-sm mono">{shortId(doc.owner_id)}</td>
                    <td className="hide-sm">{formatBytes(doc.file_size_bytes)}</td>
                    <td>
                      <PermissionBadge permission={doc.effective_permission} />
                    </td>
                    <td className="hide-sm">{formatDate(doc.updated_at)}</td>
                    <td>
                      <div className="cell-actions">
                        <Link
                          to={`/documents/${doc.id}`}
                          state={{ effectivePermission: doc.effective_permission }}
                          className="btn btn-secondary btn-sm"
                        >
                          <FileIcon width={14} height={14} />
                          Open
                        </Link>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleDownload(doc)}
                          disabled={downloadingId === doc.id}
                        >
                          <DownloadIcon width={14} height={14} />
                          {downloadingId === doc.id ? 'Downloading…' : 'Download'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </AppShell>
  );
}
