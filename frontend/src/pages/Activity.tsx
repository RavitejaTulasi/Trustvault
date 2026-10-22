import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Link } from 'react-router-dom';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import EmptyState from '../components/EmptyState';
import Tabs from '../components/Tabs';
import { OutcomeBadge } from '../components/Badges';
import {
  ActivityIcon,
  BadgeCheckIcon,
  PlusIcon,
  RefreshIcon,
  ShieldAlertIcon,
  ShieldIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import { useToast } from '../components/useToast';
import {
  createAuditCheckpoint,
  getAuditCheckpoint,
  getHealth,
  listAuditEvents,
  listDocumentActivity,
  verifyAuditChain,
  verifyAuditCheckpoint,
} from '../api';
import { describeError, formatDateTime, shortId } from '../lib/format';
import { isCheckpointAnchoringOperational } from '../lib/checkpoint';
import type {
  AuditCheckpointCreateResponse,
  AuditCheckpointInfoResponse,
  AuditCheckpointVerificationResponse,
  AuditEventListParams,
  AuditEventResponse,
  AuditOutcome,
  AuditVerificationResponse,
  HealthResponse,
} from '../types';

const PAGE_SIZE = 25;
const OUTCOMES: Array<{ value: '' | AuditOutcome; label: string }> = [
  { value: '', label: 'All outcomes' },
  { value: 'SUCCESS', label: 'Success' },
  { value: 'DENIED', label: 'Denied' },
  { value: 'FAILURE', label: 'Failure' },
];

interface AuditFilters {
  outcome: '' | AuditOutcome;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  timestampFrom: string;
  timestampTo: string;
}

const EMPTY_FILTERS: AuditFilters = {
  outcome: '',
  actorId: '',
  action: '',
  resourceType: '',
  resourceId: '',
  timestampFrom: '',
  timestampTo: '',
};

function toIsoTimestamp(value: string): string | undefined {
  if (value === '') {
    return undefined;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return undefined;
  }
  return parsed.toISOString();
}

function buildAuditParams(filters: AuditFilters, page: number): AuditEventListParams {
  return {
    page,
    page_size: PAGE_SIZE,
    outcome: filters.outcome === '' ? undefined : filters.outcome,
    actor_id: filters.actorId.trim() === '' ? undefined : filters.actorId.trim(),
    action: filters.action.trim() === '' ? undefined : filters.action.trim(),
    resource_type: filters.resourceType.trim() === '' ? undefined : filters.resourceType.trim(),
    resource_id: filters.resourceId.trim() === '' ? undefined : filters.resourceId.trim(),
    timestamp_from: toIsoTimestamp(filters.timestampFrom),
    timestamp_to: toIsoTimestamp(filters.timestampTo),
  };
}

function hasActiveFilters(filters: AuditFilters): boolean {
  return (
    filters.outcome !== '' ||
    filters.actorId.trim() !== '' ||
    filters.action.trim() !== '' ||
    filters.resourceType.trim() !== '' ||
    filters.resourceId.trim() !== '' ||
    filters.timestampFrom !== '' ||
    filters.timestampTo !== ''
  );
}

export default function Activity() {
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const { pushToast } = useToast();
  const [tab, setTab] = useState<'events' | 'documents' | 'verification'>('events');
  const [events, setEvents] = useState<AuditEventResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<AuditFilters>(EMPTY_FILTERS);
  const [filterError, setFilterError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [verifyResult, setVerifyResult] = useState<AuditVerificationResponse | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const [checkpoint, setCheckpoint] = useState<AuditCheckpointInfoResponse | null>(null);
  const [anchorHealth, setAnchorHealth] = useState<HealthResponse | null>(null);
  const [anchorStatusLoading, setAnchorStatusLoading] = useState(true);
  const [checkpointLoading, setCheckpointLoading] = useState(true);
  const [checkpointError, setCheckpointError] = useState<string | null>(null);
  const [confirmCreate, setConfirmCreate] = useState(false);
  const [creatingCheckpoint, setCreatingCheckpoint] = useState(false);
  const [createResult, setCreateResult] = useState<AuditCheckpointCreateResponse | null>(null);
  const [verifyingCheckpoint, setVerifyingCheckpoint] = useState(false);
  const [checkpointVerifyResult, setCheckpointVerifyResult] =
    useState<AuditCheckpointVerificationResponse | null>(null);
  const [checkpointActionError, setCheckpointActionError] = useState<string | null>(null);

  const eventsRequestRef = useRef(0);

  const isAdmin = user?.role === 'admin';

  const handleTabChange = (next: string) => {
    if (next === 'events' || next === 'documents' || next === 'verification') {
      setTab(next);
    }
  };

  const loadEvents = useCallback(async (targetPage: number, targetFilters: AuditFilters) => {
    const request = eventsRequestRef.current + 1;
    eventsRequestRef.current = request;
    setLoading(true);
    setLoadError(null);
    try {
      const result = await listAuditEvents(buildAuditParams(targetFilters, targetPage));
      if (request !== eventsRequestRef.current) {
        return;
      }
      setEvents(result.events);
      setTotal(result.total);
      setPage(result.page);
      setLoading(false);
    } catch (err) {
      if (request !== eventsRequestRef.current) {
        return;
      }
      setLoading(false);
      setLoadError(describeError(err, 'Could not load the audit trail'));
    }
  }, []);

  const loadCheckpoint = useCallback(async () => {
    setCheckpointLoading(true);
    setCheckpointError(null);
    try {
      const result = await getAuditCheckpoint();
      setCheckpoint(result);
      setCheckpointLoading(false);
    } catch (err) {
      setCheckpointLoading(false);
      setCheckpointError(describeError(err, 'Could not load the latest checkpoint'));
    }
  }, []);

  const loadAnchorStatus = useCallback(async () => {
    setAnchorStatusLoading(true);
    try {
      const health = await getHealth();
      setAnchorHealth(health);
      if (isCheckpointAnchoringOperational(health)) {
        await loadCheckpoint();
      } else {
        setCheckpoint(null);
        setCheckpointLoading(false);
        setCheckpointError(null);
      }
    } catch {
      setAnchorHealth(null);
      setCheckpoint(null);
      setCheckpointLoading(false);
      setCheckpointError(null);
    } finally {
      setAnchorStatusLoading(false);
    }
  }, [loadCheckpoint]);

  useEffect(() => {
    if (isAdmin) {
      // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
      void loadEvents(1, EMPTY_FILTERS);
      void loadAnchorStatus();
    }
  }, [isAdmin, loadEvents, loadAnchorStatus]);

  const updateFilter = (key: keyof AuditFilters, value: string) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const handleApplyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const from = toIsoTimestamp(filters.timestampFrom);
    const to = toIsoTimestamp(filters.timestampTo);
    if (from !== undefined && to !== undefined && from > to) {
      setFilterError('The start time must be before the end time.');
      return;
    }
    setFilterError(null);
    setAppliedFilters(filters);
    void loadEvents(1, filters);
  };

  const handleResetFilters = () => {
    setFilters(EMPTY_FILTERS);
    setAppliedFilters(EMPTY_FILTERS);
    setFilterError(null);
    void loadEvents(1, EMPTY_FILTERS);
  };

  const handleVerify = async () => {
    setVerifying(true);
    setVerifyError(null);
    try {
      const result = await verifyAuditChain();
      setVerifyResult(result);
    } catch (err) {
      setVerifyError(describeError(err, 'Audit verification failed'));
    } finally {
      setVerifying(false);
    }
  };

  const handleCreateCheckpoint = async () => {
    setCreatingCheckpoint(true);
    setCheckpointActionError(null);
    try {
      const result = await createAuditCheckpoint();
      setCreateResult(result);
      setConfirmCreate(false);
      pushToast({
        title: result.status === 'CREATED' ? 'Checkpoint created' : 'Checkpoint already present',
        description: `Sequence ${result.sequence_number} · ${result.anchor_mode}`,
        tone: result.status === 'CREATED' ? 'success' : 'info',
      });
      void loadCheckpoint();
    } catch (err) {
      setCheckpointActionError(describeError(err, 'Could not create a checkpoint'));
    } finally {
      setCreatingCheckpoint(false);
    }
  };

  const handleVerifyCheckpoint = async () => {
    setVerifyingCheckpoint(true);
    setCheckpointActionError(null);
    try {
      const result = await verifyAuditCheckpoint();
      setCheckpointVerifyResult(result);
      pushToast({
        title:
          result.status === 'VALID'
            ? 'Checkpoint verified'
            : `Checkpoint verification ${result.status.toLowerCase()}`,
        tone: result.status === 'VALID' ? 'success' : 'error',
      });
    } catch (err) {
      setCheckpointActionError(describeError(err, 'Checkpoint verification failed'));
    } finally {
      setVerifyingCheckpoint(false);
    }
  };

  if (sessionLoading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <ActivityIcon width={24} height={24} />
        </span>
        <p>Loading audit access…</p>
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

  if (!isAdmin) {
    return (
      <AppShell user={user}>
        <PageHeader
          eyebrow="Audit"
          title="Audit"
          description="The audit trail and document activity are restricted to administrators."
          backTo="/"
          backLabel="Overview"
        />
        <div className="panel">
          <EmptyState
            title="Administrator access required"
            description="Your account does not have permission to read the audit trail. No audit data was requested."
            action={
              <Link to="/" className="btn btn-secondary btn-sm">
                Back to overview
              </Link>
            }
          />
        </div>
      </AppShell>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasPrev = page > 1 && !loading;
  const hasNext = page < totalPages && !loading;
  const availableCheckpoint = checkpoint?.available === true ? checkpoint : null;
  const checkpointOperational = isCheckpointAnchoringOperational(anchorHealth);
  const checkpointActionsDisabled = checkpointLoading;
  const filtering = hasActiveFilters(appliedFilters);

  return (
    <AppShell user={user}>
      <PageHeader
        eyebrow="Administration"
        title="Audit"
        description="Inspect sensitive actions, focus on document activity, or verify the workspace audit chain."
        backTo="/"
        backLabel="Overview"
      />

      <Tabs
        label="Audit sections"
        tabs={[
          { id: 'events', label: 'Audit events' },
          { id: 'documents', label: 'Document activity' },
          { id: 'verification', label: 'Verification' },
        ]}
        value={tab}
        onChange={handleTabChange}
      />

      {tab === 'verification' && (
        <div role="tabpanel" aria-label="Verification" className="tab-panel">
      <section className="audit-verify" aria-labelledby="verify-title">
        <div className="audit-verify-copy">
          <h2 id="verify-title" className="audit-verify-title">
            <ShieldIcon width={16} height={16} /> Audit chain verification
          </h2>
          <p className="audit-verify-description">
            Validates sequence continuity and record hashes over the configured bounded
            window. Verification is rate-limited by the server.
          </p>
          {verifyError && (
            <p role="alert" className="field-error" style={{ marginTop: 6 }}>
              {verifyError}
            </p>
          )}
          {verifyResult && (
            <p className="audit-verify-result" style={{ marginTop: 6 }} role="status">
              {verifyResult.status} · {verifyResult.records_verified} record
              {verifyResult.records_verified === 1 ? '' : 's'} verified
              {verifyResult.failure_reason ? ` · ${verifyResult.failure_reason}` : ''}
            </p>
          )}
        </div>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void handleVerify()}
          disabled={verifying}
        >
          {verifyResult?.status === 'VALID' ? (
            <BadgeCheckIcon width={16} height={16} />
          ) : (
            <ShieldAlertIcon width={16} height={16} />
          )}
          {verifying ? 'Verifying…' : 'Verify chain'}
        </button>
      </section>

      {!checkpointOperational && !anchorStatusLoading && (
        <p className="anchoring-note" role="note">
          Independent checkpoint anchoring is not configured for this deployment.
          Chain verification above still validates local record hashes and sequence
          continuity; it is not an external anchor.
        </p>
      )}

      {checkpointOperational && (
      <section className="checkpoint-panel" aria-labelledby="checkpoint-title">
        <div className="checkpoint-header">
          <div className="checkpoint-copy">
            <h2 id="checkpoint-title" className="checkpoint-title">
              <ShieldIcon width={16} height={16} /> Checkpoint anchor
            </h2>
            <p className="checkpoint-description">
              A checkpoint pins the current chain head in the configured anchor store.
              Verification compares the live chain against that stored anchor.
            </p>
          </div>
          <div className="checkpoint-actions">
            {confirmCreate ? (
              <div className="checkpoint-confirm" role="group" aria-label="Confirm checkpoint creation">
                <span className="checkpoint-confirm-text">Anchor the current chain head?</span>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={() => void handleCreateCheckpoint()}
                  disabled={creatingCheckpoint}
                >
                  {creatingCheckpoint ? 'Creating…' : 'Confirm create checkpoint'}
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => setConfirmCreate(false)}
                  disabled={creatingCheckpoint}
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  setConfirmCreate(true);
                  setCheckpointActionError(null);
                }}
                disabled={
                  creatingCheckpoint || verifyingCheckpoint || checkpointActionsDisabled
                }
              >
                <PlusIcon width={15} height={15} />
                Create checkpoint
              </button>
            )}
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => void handleVerifyCheckpoint()}
              disabled={
                verifyingCheckpoint || creatingCheckpoint || checkpointActionsDisabled
              }
            >
              <BadgeCheckIcon width={15} height={15} />
              {verifyingCheckpoint ? 'Verifying…' : 'Verify against checkpoint'}
            </button>
          </div>
        </div>

        {checkpointLoading ? (
          <p className="checkpoint-loading" role="status">
            Loading latest checkpoint…
          </p>
        ) : (
          <dl className="checkpoint-meta">
            <div>
              <dt>Status</dt>
              <dd>{availableCheckpoint ? 'Available' : 'Not created'}</dd>
            </div>
            {checkpoint && (
              <div>
                <dt>Anchor mode</dt>
                <dd className="mono">
                  {checkpoint.anchor_mode === 'local_file'
                    ? 'local file (not independent)'
                    : checkpoint.anchor_mode}
                </dd>
              </div>
            )}
            {availableCheckpoint && availableCheckpoint.sequence_number !== null && (
              <div>
                <dt>Sequence</dt>
                <dd className="mono">{availableCheckpoint.sequence_number}</dd>
              </div>
            )}
            {availableCheckpoint && availableCheckpoint.created_at !== null && (
              <div>
                <dt>Created</dt>
                <dd>{formatDateTime(availableCheckpoint.created_at)}</dd>
              </div>
            )}
            {availableCheckpoint && availableCheckpoint.format_version !== null && (
              <div>
                <dt>Format</dt>
                <dd className="mono">v{availableCheckpoint.format_version}</dd>
              </div>
            )}
          </dl>
        )}

        {checkpointError && (
          <p role="alert" className="field-error" style={{ marginTop: 8 }}>
            {checkpointError}
          </p>
        )}
        {checkpointActionError && (
          <p role="alert" className="field-error" style={{ marginTop: 8 }}>
            {checkpointActionError}
          </p>
        )}
        {createResult && (
          <p className="checkpoint-result" style={{ marginTop: 10 }} role="status">
            {createResult.status === 'CREATED' ? 'Checkpoint created' : 'Checkpoint already present'} ·
            sequence {createResult.sequence_number} · {createResult.anchor_mode} ·{' '}
            {formatDateTime(createResult.created_at)}
          </p>
        )}
        {checkpointVerifyResult && (
          <p
            className={
              checkpointVerifyResult.status === 'VALID'
                ? 'checkpoint-result'
                : 'checkpoint-result is-error'
            }
            style={{ marginTop: 10 }}
            role="status"
          >
            {checkpointVerifyResult.status} · {checkpointVerifyResult.records_verified} record
            {checkpointVerifyResult.records_verified === 1 ? '' : 's'} verified
            {checkpointVerifyResult.checkpoint_sequence !== null
              ? ` · checkpoint seq ${checkpointVerifyResult.checkpoint_sequence}`
              : ''}
            {checkpointVerifyResult.chain_head_sequence !== null
              ? ` · chain head ${checkpointVerifyResult.chain_head_sequence}`
              : ''}
            {checkpointVerifyResult.failure_reason
              ? ` · ${checkpointVerifyResult.failure_reason}`
              : ''}
          </p>
        )}
      </section>
      )}
        </div>
      )}

      {tab === 'events' && (
        <div role="tabpanel" aria-label="Audit events" className="tab-panel">
      <form className="audit-filters" aria-label="Audit event filters" onSubmit={handleApplyFilters}>
        <div className="field field-compact">
          <label htmlFor="audit-outcome">Outcome</label>
          <select
            id="audit-outcome"
            className="select"
            value={filters.outcome}
            onChange={(e) => updateFilter('outcome', e.target.value)}
          >
            {OUTCOMES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-actor">Actor ID</label>
          <input
            id="audit-actor"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={filters.actorId}
            onChange={(e) => updateFilter('actorId', e.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-action">Action</label>
          <input
            id="audit-action"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="document.download"
            value={filters.action}
            onChange={(e) => updateFilter('action', e.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-resource-type">Resource type</label>
          <input
            id="audit-resource-type"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={filters.resourceType}
            onChange={(e) => updateFilter('resourceType', e.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-resource-id">Resource ID</label>
          <input
            id="audit-resource-id"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={filters.resourceId}
            onChange={(e) => updateFilter('resourceId', e.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-from">From</label>
          <input
            id="audit-from"
            className="input"
            type="datetime-local"
            value={filters.timestampFrom}
            onChange={(e) => updateFilter('timestampFrom', e.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="audit-to">To</label>
          <input
            id="audit-to"
            className="input"
            type="datetime-local"
            value={filters.timestampTo}
            onChange={(e) => updateFilter('timestampTo', e.target.value)}
          />
        </div>
        <div className="audit-filter-actions">
          <button type="submit" className="btn btn-secondary btn-sm">
            Apply filters
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={handleResetFilters}
            disabled={!filtering && !hasActiveFilters(filters)}
          >
            Reset
          </button>
        </div>
      </form>

      {filterError && (
        <p role="alert" className="field-error" style={{ marginBottom: 14 }}>
          {filterError}
        </p>
      )}

      {loadError && (
        <div role="alert" className="alert alert-error">
          {loadError}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void loadEvents(page, appliedFilters)}
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="panel" aria-busy="true">
          <div className="skeleton-table">
            {[0, 1, 2, 3, 4].map((row) => (
              <div key={row} className="skeleton skeleton-line" />
            ))}
          </div>
        </div>
      ) : events.length === 0 ? (
        <div className="panel">
          <EmptyState
            title="No audit events"
            description={
              filtering
                ? 'No events match the current filters. Adjust or reset the filters and try again.'
                : 'Sensitive actions will appear here as they occur.'
            }
          />
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <caption>{total} audit events</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col" className="hide-sm">
                    Seq
                  </th>
                  <th scope="col">Action</th>
                  <th scope="col" className="hide-sm">
                    Actor
                  </th>
                  <th scope="col" className="hide-sm">
                    Target
                  </th>
                  <th scope="col">Outcome</th>
                  <th scope="col" className="hide-sm">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDateTime(event.timestamp)}</td>
                    <td className="hide-sm mono">{event.sequence_number}</td>
                    <td>
                      <span className="cell-title-link">{event.action}</span>
                    </td>
                    <td className="hide-sm mono">{shortId(event.actor_id)}</td>
                    <td className="hide-sm">
                      <div className="cell-title">
                        <span className="cell-sub">
                          {event.resource_type ?? '—'}
                          {event.resource_id ? ` · ${shortId(event.resource_id)}` : ''}
                        </span>
                      </div>
                    </td>
                    <td>
                      <OutcomeBadge outcome={event.outcome} />
                    </td>
                    <td className="hide-sm details-cell">
                      {event.details ? (
                        <div className="detail-chips">
                          {Object.entries(event.details).map(([key, value]) => (
                            <span key={key} className="detail-chip">
                              {key}:{' '}
                              {typeof value === 'object' && value !== null
                                ? JSON.stringify(value)
                                : String(value)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="cell-sub">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="table-meta">
            <span>Newest first · reading this page is audit-logged</span>
            <nav className="pagination" aria-label="Audit pagination">
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <div className="pagination-controls">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasPrev}
                  onClick={() => void loadEvents(page - 1, appliedFilters)}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasNext}
                  onClick={() => void loadEvents(page + 1, appliedFilters)}
                >
                  Next
                </button>
              </div>
            </nav>
          </div>
        </>
      )}
        </div>
      )}

      {tab === 'documents' && <DocumentActivityTab />}
    </AppShell>
  );
}

interface DocumentFilters {
  documentId: string;
  actorId: string;
  action: string;
  outcome: '' | AuditOutcome;
}

const EMPTY_DOCUMENT_FILTERS: DocumentFilters = {
  documentId: '',
  actorId: '',
  action: '',
  outcome: '',
};

function DocumentActivityTab() {
  const [events, setEvents] = useState<AuditEventResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<DocumentFilters>(EMPTY_DOCUMENT_FILTERS);
  const [appliedFilters, setAppliedFilters] =
    useState<DocumentFilters>(EMPTY_DOCUMENT_FILTERS);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const requestRef = useRef(0);

  const loadActivity = useCallback(
    async (targetPage: number, targetFilters: DocumentFilters) => {
      const request = requestRef.current + 1;
      requestRef.current = request;
      setLoading(true);
      setLoadError(null);
      try {
        const result = await listDocumentActivity({
          page: targetPage,
          page_size: PAGE_SIZE,
          document_id: targetFilters.documentId.trim() || undefined,
          actor_id: targetFilters.actorId.trim() || undefined,
          action: targetFilters.action.trim() || undefined,
          outcome: targetFilters.outcome === '' ? undefined : targetFilters.outcome,
        });
        if (request !== requestRef.current) {
          return;
        }
        setEvents(result.events);
        setTotal(result.total);
        setPage(result.page);
      } catch (err) {
        if (request !== requestRef.current) {
          return;
        }
        setLoadError(describeError(err, 'Could not load document activity'));
      } finally {
        if (request === requestRef.current) {
          setLoading(false);
        }
      }
    },
    [],
  );

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- tab fetch reflects server state
    void loadActivity(1, EMPTY_DOCUMENT_FILTERS);
  }, [loadActivity]);

  const updateFilter = (key: keyof DocumentFilters, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
  };

  const handleApplyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAppliedFilters(filters);
    void loadActivity(1, filters);
  };

  const handleResetFilters = () => {
    setFilters(EMPTY_DOCUMENT_FILTERS);
    setAppliedFilters(EMPTY_DOCUMENT_FILTERS);
    void loadActivity(1, EMPTY_DOCUMENT_FILTERS);
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasPrev = page > 1 && !loading;
  const hasNext = page < totalPages && !loading;
  const filtering =
    appliedFilters.documentId.trim() !== '' ||
    appliedFilters.actorId.trim() !== '' ||
    appliedFilters.action.trim() !== '' ||
    appliedFilters.outcome !== '';

  return (
    <div role="tabpanel" aria-label="Document activity" className="tab-panel">
      <form className="audit-filters" aria-label="Document activity filters" onSubmit={handleApplyFilters}>
        <div className="field field-compact">
          <label htmlFor="document-activity-id">Document ID</label>
          <input
            id="document-activity-id"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="Filter by document ID"
            value={filters.documentId}
            onChange={(event) => updateFilter('documentId', event.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="document-activity-actor">Actor ID</label>
          <input
            id="document-activity-actor"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            value={filters.actorId}
            onChange={(event) => updateFilter('actorId', event.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="document-activity-action">Action</label>
          <input
            id="document-activity-action"
            className="input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            placeholder="document.download"
            value={filters.action}
            onChange={(event) => updateFilter('action', event.target.value)}
          />
        </div>
        <div className="field field-compact">
          <label htmlFor="document-activity-outcome">Outcome</label>
          <select
            id="document-activity-outcome"
            className="select"
            value={filters.outcome}
            onChange={(event) => updateFilter('outcome', event.target.value)}
          >
            {OUTCOMES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="audit-filter-actions">
          <button type="submit" className="btn btn-secondary btn-sm">
            Apply filters
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={handleResetFilters}
            disabled={
              !filtering &&
              filters.documentId.trim() === '' &&
              filters.actorId.trim() === '' &&
              filters.action.trim() === '' &&
              filters.outcome === ''
            }
          >
            Reset
          </button>
        </div>
      </form>

      {loadError && (
        <div role="alert" className="alert alert-error">
          {loadError}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void loadActivity(page, appliedFilters)}
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="panel" aria-busy="true">
          <div className="skeleton-table">
            {[0, 1, 2, 3, 4].map((row) => (
              <div key={row} className="skeleton skeleton-line" />
            ))}
          </div>
        </div>
      ) : events.length === 0 ? (
        <div className="panel">
          <EmptyState
            title="No document activity"
            description={
              filtering
                ? 'No document events match the current filters.'
                : 'Document uploads, downloads, changes, and grants will appear here.'
            }
          />
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <caption>{total} document events</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Action</th>
                  <th scope="col" className="hide-sm">
                    Actor
                  </th>
                  <th scope="col" className="hide-sm">
                    Target
                  </th>
                  <th scope="col">Outcome</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDateTime(event.timestamp)}</td>
                    <td>
                      <span className="cell-title-link">{event.action}</span>
                    </td>
                    <td className="hide-sm mono">{shortId(event.actor_id)}</td>
                    <td className="hide-sm">
                      <span className="cell-sub">
                        {event.resource_type ?? '—'}
                        {event.resource_id ? ` · ${shortId(event.resource_id)}` : ''}
                      </span>
                    </td>
                    <td>
                      <OutcomeBadge outcome={event.outcome} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="table-meta">
            <span>Newest first · document and grant events</span>
            <nav className="pagination" aria-label="Document activity pagination">
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <div className="pagination-controls">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasPrev}
                  onClick={() => void loadActivity(page - 1, appliedFilters)}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasNext}
                  onClick={() => void loadActivity(page + 1, appliedFilters)}
                >
                  Next
                </button>
              </div>
            </nav>
          </div>
        </>
      )}
    </div>
  );
}
