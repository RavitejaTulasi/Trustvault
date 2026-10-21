import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { deleteDocument, downloadDocument, getMe, listDocuments, uploadDocument } from '../auth';
import { ApiError, NetworkError } from '../api';
import type { DocumentListItem, UserResponse } from '../types';

const PAGE_SIZE = 25;

function formatBytes(bytes: number): string {
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

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toISOString().slice(0, 10);
}

function describeActionError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    return err.detail;
  }
  if (err instanceof NetworkError) {
    return err.message;
  }
  return fallback;
}

function canUpload(user: UserResponse | null): boolean {
  return user !== null && (user.role === 'owner' || user.role === 'admin');
}

export default function Documents() {
  const navigate = useNavigate();

  const [user, setUser] = useState<UserResponse | null>(null);
  const [documents, setDocuments] = useState<DocumentListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Draft inputs (editable) vs applied filters (drive the request).
  const [searchDraft, setSearchDraft] = useState('');
  const [categoryDraft, setCategoryDraft] = useState('');
  const [appliedSearch, setAppliedSearch] = useState('');
  const [appliedCategory, setAppliedCategory] = useState('');

  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadCategory, setUploadCategory] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
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
        setLoadError(describeActionError(err, 'Could not load documents'));
      } finally {
        setLoading(false);
      }
    },
    [navigate],
  );

  const loadSessionAndDocuments = useCallback(async () => {
    try {
      // The leading await keeps state updates out of the effect tick.
      const session = await getMe();
      if (!session) {
        navigate('/login', { replace: true });
        return;
      }
      setUser(session);
      await loadDocuments(1, appliedSearch, appliedCategory);
    } catch (err) {
      // 5xx / network failures stay on the page with a retry option; they must
      // NOT be treated as an unauthenticated session.
      setLoading(false);
      setLoadError(describeActionError(err, 'Could not load your session'));
    }
  }, [appliedCategory, appliedSearch, loadDocuments, navigate]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- external backend sync; setState runs after awaits
    loadSessionAndDocuments();
  }, [loadSessionAndDocuments]);

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

  const handleUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setUploadError(null);
    if (!uploadFile || uploadTitle.trim() === '') {
      setUploadError('A file and a title are required.');
      return;
    }
    setUploading(true);
    try {
      await uploadDocument(uploadFile, uploadTitle.trim(), uploadCategory.trim() || undefined);
      setUploadFile(null);
      setUploadTitle('');
      setUploadCategory('');
      const fileInput = document.querySelector<HTMLInputElement>('#upload-file');
      if (fileInput) {
        fileInput.value = '';
      }
      await loadDocuments(1, appliedSearch, appliedCategory);
    } catch (err) {
      setUploadError(describeActionError(err, 'Upload failed. Please try again.'));
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
      setActionError(describeActionError(err, `Could not download "${doc.title}"`));
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
    } catch (err) {
      setActionError(describeActionError(err, `Could not delete "${doc.title}"`));
    } finally {
      setDeletingId(null);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasPrev = page > 1 && !loading;
  const hasNext = page < totalPages && !loading;

  return (
    <main className="documents-page">
      <header>
        <h2>Documents</h2>
        <p>
          Signed in as {user?.full_name} ({user?.role}) ·{' '}
          <Link to="/dashboard">Dashboard</Link>
        </p>
      </header>

      {loadError && (
        <p role="alert" className="error">
          {loadError}{' '}
          <button type="button" onClick={loadSessionAndDocuments}>
            Retry
          </button>
        </p>
      )}

      <form onSubmit={handleSearch} className="search-form" aria-label="Search documents">
        <div>
          <label htmlFor="search-q">Search</label>
          <input
            id="search-q"
            type="text"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            placeholder="Title or filename"
            maxLength={255}
          />
        </div>
        <div>
          <label htmlFor="search-category">Category</label>
          <input
            id="search-category"
            type="text"
            value={categoryDraft}
            onChange={(e) => setCategoryDraft(e.target.value)}
            placeholder="Category"
            maxLength={100}
          />
        </div>
        <button type="submit">Search</button>
        <button type="button" onClick={handleClearFilters}>
          Clear
        </button>
      </form>

      {canUpload(user) && (
        <form onSubmit={handleUpload} className="upload-form" aria-label="Upload a document">
          <h3>Upload a document</h3>
          {uploadError && (
            <p role="alert" className="error">
              {uploadError}
            </p>
          )}
          <div>
            <label htmlFor="upload-file">File</label>
            <input
              id="upload-file"
              type="file"
              onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
            />
          </div>
          <div>
            <label htmlFor="upload-title">Title</label>
            <input
              id="upload-title"
              type="text"
              value={uploadTitle}
              onChange={(e) => setUploadTitle(e.target.value)}
              maxLength={255}
              required
            />
          </div>
          <div>
            <label htmlFor="upload-category">Category (optional)</label>
            <input
              id="upload-category"
              type="text"
              value={uploadCategory}
              onChange={(e) => setUploadCategory(e.target.value)}
              maxLength={100}
              placeholder="General"
            />
          </div>
          <button type="submit" disabled={uploading}>
            {uploading ? 'Uploading…' : 'Upload'}
          </button>
        </form>
      )}

      {actionError && (
        <p role="alert" className="error">
          {actionError}
        </p>
      )}

      {loading ? (
        <p aria-busy="true">Loading…</p>
      ) : documents.length === 0 ? (
        <p>No documents found.</p>
      ) : (
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
                  <Link to={`/documents/${doc.id}`}>{doc.title}</Link>
                </td>
                <td>{doc.original_filename}</td>
                <td>{formatBytes(doc.file_size_bytes)}</td>
                <td>{doc.category}</td>
                <td>
                  <span className={`permission permission-${doc.effective_permission}`}>
                    {doc.effective_permission}
                  </span>
                </td>
                <td>{formatDate(doc.created_at)}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => handleDownload(doc)}
                    disabled={downloadingId === doc.id}
                  >
                    {downloadingId === doc.id ? 'Downloading…' : 'Download'}
                  </button>
                  {doc.effective_permission === 'owner' && (
                    <button
                      type="button"
                      onClick={() => handleDelete(doc)}
                      disabled={deletingId === doc.id}
                    >
                      {deleteArmedId === doc.id
                        ? 'Confirm delete?'
                        : deletingId === doc.id
                          ? 'Deleting…'
                          : 'Delete'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <nav className="pagination" aria-label="Documents pagination">
        <button
          type="button"
          disabled={!hasPrev}
          onClick={() => loadDocuments(page - 1, appliedSearch, appliedCategory)}
        >
          Previous
        </button>
        <span>
          Page {page} of {totalPages}
        </span>
        <button
          type="button"
          disabled={!hasNext}
          onClick={() => loadDocuments(page + 1, appliedSearch, appliedCategory)}
        >
          Next
        </button>
      </nav>
    </main>
  );
}
