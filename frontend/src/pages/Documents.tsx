import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
  deleteDocument,
  downloadDocument,
  listDocuments,
  uploadDocument,
} from '../auth';
import { ApiError } from '../api';
import type { DocumentListItem } from '../types';
import AppShell from '../components/AppShell';
import EmptyState from '../components/EmptyState';
import PageHeader from '../components/PageHeader';
import Skeleton from '../components/Skeleton';
import { PermissionBadge } from '../components/Badges';
import { useToast } from '../components/useToast';
import {
  DownloadIcon,
  RefreshIcon,
  SearchIcon,
  ShieldIcon,
  TrashIcon,
  UploadIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import { canManageDocuments } from '../lib/navigation';
import { describeError, formatBytes, formatDate } from '../lib/format';

const PAGE_SIZE = 25;

export default function Documents() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const { pushToast } = useToast();
  const uploadPanelRef = useRef<HTMLElement>(null);

  const [documents, setDocuments] = useState<DocumentListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [searchDraft, setSearchDraft] = useState('');
  const [categoryDraft, setCategoryDraft] = useState('');
  const [appliedSearch, setAppliedSearch] = useState('');
  const [appliedCategory, setAppliedCategory] = useState('');

  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadCategory, setUploadCategory] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [reviewingUpload, setReviewingUpload] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [actionError, setActionError] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [deleteArmedId, setDeleteArmedId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadDocuments = useCallback(
    async (targetPage: number, search: string, category: string) => {
      setLoading(true);
      setLoadError(null);
      try {
        const result = await listDocuments({
          page: targetPage,
          page_size: PAGE_SIZE,
          q: search,
          category,
        });
        setDocuments(result.documents);
        setTotal(result.total);
        setPage(result.page);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          navigate('/login', { replace: true });
          return;
        }
        setLoadError(describeError(err, 'Could not load documents'));
      } finally {
        setLoading(false);
      }
    },
    [navigate],
  );

  useEffect(() => {
    if (!user) {
      return;
    }
    // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
    void loadDocuments(1, appliedSearch, appliedCategory);
  }, [appliedCategory, appliedSearch, loadDocuments, user]);

  useEffect(() => {
    if (searchParams.get('upload') !== '1') {
      return;
    }
    uploadPanelRef.current?.scrollIntoView?.({ block: 'center' });
    document.querySelector<HTMLInputElement>('#upload-file')?.focus();
  }, [searchParams, user]);

  const handleSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAppliedSearch(searchDraft.trim());
    setAppliedCategory(categoryDraft.trim());
  };

  const handleClearFilters = () => {
    setSearchDraft('');
    setCategoryDraft('');
    setAppliedSearch('');
    setAppliedCategory('');
    setUploadError(null);
  };

  const handleUpload = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setUploadError(null);
    if (!uploadFile || uploadTitle.trim() === '') {
      setUploadError('A file and a title are required.');
      return;
    }
    setReviewingUpload(true);
  };

  const handleConfirmUpload = async () => {
    setUploadError(null);
    if (!uploadFile || uploadTitle.trim() === '') {
      setUploadError('A file and a title are required.');
      setReviewingUpload(false);
      return;
    }
    setUploading(true);
    try {
      const uploaded = await uploadDocument(
        uploadFile,
        uploadTitle.trim(),
        uploadCategory.trim() || undefined,
      );
      setUploadFile(null);
      setUploadTitle('');
      setUploadCategory('');
      setReviewingUpload(false);
      const fileInput = document.querySelector<HTMLInputElement>('#upload-file');
      if (fileInput) {
        fileInput.value = '';
      }
      await loadDocuments(1, appliedSearch, appliedCategory);
      pushToast({
        title: 'Document uploaded',
        description: `“${uploaded.title}” is now available in your library.`,
        tone: 'success',
      });
    } catch (err) {
      setUploadError(describeError(err, 'Upload failed. Please try again.'));
    } finally {
      setUploading(false);
    }
  };

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

  const handleDelete = async (doc: DocumentListItem) => {
    if (deleteArmedId !== doc.id) {
      setDeleteArmedId(doc.id);
      return;
    }
    setDeleteArmedId(null);
    setActionError(null);
    setDeletingId(doc.id);
    try {
      await deleteDocument(doc.id);
      await loadDocuments(page, appliedSearch, appliedCategory);
      pushToast({
        title: 'Document deleted',
        description: `“${doc.title}” was removed from your library.`,
        tone: 'success',
      });
    } catch (err) {
      setActionError(describeError(err, `Could not delete "${doc.title}"`));
    } finally {
      setDeletingId(null);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasPrev = page > 1 && !loading;
  const hasNext = page < totalPages && !loading;

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
            <p className="section-copy">Loading your document library…</p>
          </>
        )}
      </main>
    );
  }

  const canUpload = canManageDocuments(user.role);

  return (
    <AppShell user={user}>
      <div className="documents-page">
        <PageHeader
          eyebrow="Library"
          title="Documents"
          description="Search visible files, upload as an owner or administrator, and act only on the permissions the server returns."
          backTo="/"
          backLabel="Overview"
        />

        {loadError && (
          <div role="alert" className="alert alert-error">
            {loadError}
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => void loadDocuments(page, appliedSearch, appliedCategory)}
            >
              <RefreshIcon width={14} height={14} />
              Retry
            </button>
          </div>
        )}

        <form onSubmit={handleSearch} className="search-form" aria-label="Search documents">
          <div className="field">
            <label htmlFor="search-q">Search</label>
            <input
              id="search-q"
              className="input"
              type="text"
              value={searchDraft}
              onChange={(e) => setSearchDraft(e.target.value)}
              placeholder="Title or filename"
              maxLength={255}
            />
          </div>
          <div className="field">
            <label htmlFor="search-category">Category</label>
            <input
              id="search-category"
              className="input"
              type="text"
              value={categoryDraft}
              onChange={(e) => setCategoryDraft(e.target.value)}
              placeholder="Category"
              maxLength={100}
            />
          </div>
          <button type="submit" className="btn btn-primary">
            <SearchIcon width={15} height={15} />
            Search
          </button>
          <button type="button" className="btn btn-ghost" onClick={handleClearFilters}>
            Clear
          </button>
        </form>

        {canUpload && (
          <section
            ref={uploadPanelRef}
            className="panel upload-panel"
            aria-labelledby="upload-panel-title"
          >
            <div className="panel-header">
              <div>
                <h2 id="upload-panel-title" className="panel-title">
                  Upload a document
                </h2>
                <p className="panel-description">
                  Owners and administrators can add files to the library.
                </p>
              </div>
              <span className="badge badge-owner">
                <UploadIcon width={12} height={12} />
                Owner tools
              </span>
            </div>
            <div className="panel-body">
              {uploadError && (
                <p role="alert" className="alert alert-error">
                  {uploadError}
                </p>
              )}
              {reviewingUpload && uploadFile ? (
                <div className="upload-review" role="group" aria-label="Review upload">
                  <dl className="document-meta">
                    <dt>File</dt>
                    <dd className="mono">{uploadFile.name}</dd>
                    <dt>Size</dt>
                    <dd>{formatBytes(uploadFile.size)}</dd>
                    <dt>Type</dt>
                    <dd className="mono">{uploadFile.type || 'unknown'}</dd>
                    <dt>Title</dt>
                    <dd>{uploadTitle.trim()}</dd>
                    <dt>Category</dt>
                    <dd>{uploadCategory.trim() || 'Uncategorized'}</dd>
                  </dl>
                  <div className="form-actions">
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => void handleConfirmUpload()}
                      disabled={uploading}
                    >
                      <UploadIcon width={15} height={15} />
                      {uploading ? 'Uploading…' : 'Confirm upload'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => setReviewingUpload(false)}
                      disabled={uploading}
                    >
                      Back
                    </button>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleUpload} className="upload-form" aria-label="Upload a document">
                <div className="field">
                  <label htmlFor="upload-file">File</label>
                  <input
                    id="upload-file"
                    type="file"
                    onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="upload-title">Title</label>
                  <input
                    id="upload-title"
                    className="input"
                    type="text"
                    value={uploadTitle}
                    onChange={(e) => setUploadTitle(e.target.value)}
                    maxLength={255}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="upload-category">Category (optional)</label>
                  <input
                    id="upload-category"
                    className="input"
                    type="text"
                    value={uploadCategory}
                    onChange={(e) => setUploadCategory(e.target.value)}
                    maxLength={100}
                    placeholder="General"
                  />
                </div>
                <button type="submit" className="btn btn-primary" disabled={uploading}>
                  <UploadIcon width={15} height={15} />
                  Review upload
                </button>
              </form>
              )}
            </div>
          </section>
        )}

        {actionError && (
          <div role="alert" className="alert alert-error">
            {actionError}
          </div>
        )}

        {loading ? (
          <div className="panel" aria-busy="true">
            <div className="panel-body">
              <Skeleton lines={6} label="Loading documents" />
            </div>
          </div>
        ) : documents.length === 0 ? (
          <div className="panel empty-panel">
            <EmptyState
              title="No documents found."
              description={
                canUpload
                  ? 'Upload a file above, or adjust the current filters.'
                  : 'No visible documents match the current filters.'
              }
            />
          </div>
        ) : (
          <div className="table-wrap">
            <table className="documents-table">
              <caption>
                {total} document{total === 1 ? '' : 's'}
              </caption>
              <thead>
                <tr>
                  <th scope="col">Title</th>
                  <th scope="col">Filename</th>
                  <th scope="col">Size</th>
                  <th scope="col">Category</th>
                  <th scope="col">Access</th>
                  <th scope="col">Created</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((doc) => (
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
                        <span className="cell-sub">{doc.category}</span>
                      </div>
                    </td>
                    <td className="mono">{doc.original_filename}</td>
                    <td>{formatBytes(doc.file_size_bytes)}</td>
                    <td>{doc.category}</td>
                    <td>
                      <PermissionBadge permission={doc.effective_permission} />
                    </td>
                    <td>{formatDate(doc.created_at)}</td>
                    <td>
                      <div className="cell-actions">
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => void handleDownload(doc)}
                          disabled={downloadingId === doc.id}
                        >
                          <DownloadIcon width={14} height={14} />
                          {downloadingId === doc.id ? 'Downloading…' : 'Download'}
                        </button>
                        {doc.effective_permission === 'owner' && (
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            onClick={() => void handleDelete(doc)}
                            disabled={deletingId === doc.id}
                          >
                            <TrashIcon width={14} height={14} />
                            {deleteArmedId === doc.id
                              ? 'Confirm delete?'
                              : deletingId === doc.id
                                ? 'Deleting…'
                                : 'Delete'}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <nav className="pagination" aria-label="Documents pagination">
          <span className="pagination-info">
            Page {page} of {totalPages}
          </span>
          <div className="pagination-controls">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!hasPrev}
              onClick={() => void loadDocuments(page - 1, appliedSearch, appliedCategory)}
            >
              Previous
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!hasNext}
              onClick={() => void loadDocuments(page + 1, appliedSearch, appliedCategory)}
            >
              Next
            </button>
          </div>
        </nav>
      </div>
    </AppShell>
  );
}
