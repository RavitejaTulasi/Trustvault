# TrustVault — 5-Minute Video Demonstration Script

This document details the step-by-step narrative and technical demonstration sequence for the video submission.

---

## Video Outline & Timing (Total: 5:00)

### 0:00 – 0:45: Project Overview & Security Philosophy
- **Visual**: Title screen, repository architecture diagram (`docs/ARCHITECTURE.md`).
- **Narrative**: 
  - Introduce TrustVault: A production-minded secure document sharing platform with a verifiable, tamper-evident audit trail.
  - Explain the 3-tier role model: Administrator (governance & audit only), Document Owner (full document lifecycle), and Viewer (granted access only).
  - Emphasize the core security tenet: Default deny, zero client-trust, and immediate revocation.

### 0:45 – 1:30: Document Owner Workflow & Private Storage
- **Visual**: Browser at `/login`. Log in as `owner@trustvault.local`.
- **Narrative & Actions**:
  - Show owner dashboard.
  - Upload a sensitive financial document (`q3_earnings_confidential.pdf`).
  - Demonstrate file validation (show rejection if oversized or invalid type).
  - Inspect server filesystem in terminal: Show that stored file is saved in `./private_storage` under a random 256-bit hex key (`e7b4c9...`) completely decoupled from the original filename and outside the public web root.

### 1:30 – 2:30: Permission Sharing & Immediate Revocation
- **Visual**: Owner clicks "Share Document", selects `viewer@trustvault.local`, sets permission to "Read-Only".
- **Narrative & Actions**:
  - Switch browser / incognito window: Log in as `viewer@trustvault.local`.
  - Viewer sees granted document in their list.
  - Viewer successfully downloads the document bytes.
  - Viewer attempts to submit an edit or delete -> UI disables button and direct API attempt returns `403 Forbidden`.
  - **Immediate Revocation Demonstration**:
    - In Owner window: Click "Revoke Access" for Viewer.
    - In Viewer window: Immediately attempt to re-download the file.
    - Point out that the very next request is rejected with `403 Forbidden` / `404 Not Found` because the backend queries the live database transaction without relying on stale caches.

### 2:30 – 3:30: Administrator Forensics & Audit Integrity Verification
- **Visual**: Log in as `admin@trustvault.local`.
- **Narrative & Actions**:
  - Show that Admin dashboard does NOT allow browsing confidential document contents.
  - Navigate to "Audit Log & System Forensics".
  - Inspect the audit trail: Show logged events for login, upload, permission grant, download, revocation, and denied attempt.
  - Highlight the cryptographic fields: `sequence_number`, `previous_hash`, and `record_hash`.
  - Run the live integrity check: Show `verify_chain_integrity()` returning `VALID (all hashes verified)`.
  - (Terminal demonstration): Show simulated tampering detection by altering a row in SQLite/Postgres and showing the audit check immediately flagging sequence tampering.

### 3:30 – 4:30: Automated Security Testing & Authorization-Removal Experiment
- **Visual**: Terminal executing `pytest backend/tests/ -v`.
- **Narrative & Actions**:
  - Run the full suite: Show all security integration tests passing (BOLA rejection, role escalation prevention, cross-user isolation).
  - **Authorization-Removal Experiment**:
    - Open `backend/app/services/authorization.py`.
    - Temporarily comment out the grant check in `authorize_document_access`.
    - Re-run `pytest`: Point out the immediate failure in `test_unrelated_user_cannot_access_document`.
    - Restore the authorization check and re-run: All tests pass green.

### 4:30 – 5:00: Summary, Residual Risks & Deployment
- **Visual**: Live deployed application URL and GitHub repository.
- **Narrative**:
  - Summarize achievements: Strict least-privilege role matrix, server-side private storage, immediate revocation, and SHA-256 tamper-evident audit chaining.
  - Transparently state residual risks: Hash chaining requires external WORM anchoring for protection against full database overwrite; client-side file deletion cannot be enforced once downloaded.
- **Closing**: Thank the evaluation team.
